package main

import (
 	"fmt"
	"log"
	"net/http"
	"time"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"github.com/PuerkitoBio/goquery"

)

var(
	GLOBAL_DEPENDABOT_CVE_MAP = make(map[string]int)
	GLOBAL_GH_API_URL = "https://api.github.com/graphql"
	GLOBAL_EXPLOIT_DB_MAPPING_URL = "https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html"
	GLOBAL_CISA_JSON_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	GLOBAL_GH_API_TOKEN = ""
)

func main() {

	setGHToken()
	
	// setExploitDBMapping()
	// runDependabotScan()
	createDependabotCVEMap()
	runCVEDetection()

	http.HandleFunc("/api/v1/github/dependabot/all", dependabotFindings)

	fs := http.FileServer(http.Dir("./frontend"))
	http.Handle("/", fs)
	http.ListenAndServe(":8090", nil)

}

func setGHToken(){
	token := os.Getenv("GH_TOKEN")

	if token != "" {
		GLOBAL_GH_API_TOKEN = token
	} 
}

type CISAVuln struct {
	CVEID string `json:"cveID"`
}
type CISA struct {
	Vulnerabilities []CISAVuln `json:"vulnerabilities"`
}


func runCVEDetection() {
	fmt.Println("runCVEDetection..")

	vulnerabilityFeed, err := fetchCISAVulnerabilityFeed(GLOBAL_CISA_JSON_FEED_URL)
	if err != nil {
		log.Fatalf("Error fetching CISA vulnerability feed: %v", err)
	}


	for i := 0; i < len(vulnerabilityFeed.Vulnerabilities); i++ {
		
		_, okCheck := GLOBAL_DEPENDABOT_CVE_MAP[vulnerabilityFeed.Vulnerabilities[i].CVEID]
		if okCheck {
			fmt.Println("CISA - DEPENDABOT - " + vulnerabilityFeed.Vulnerabilities[i].CVEID + " EXIST !")				
		}
		
	}
	for i := 0; i < len(GLOBAL_EXPLOITDB); i++ {
	
		_, okCheck := GLOBAL_DEPENDABOT_CVE_MAP[GLOBAL_EXPLOITDB[i]]
		if okCheck {
			fmt.Println("EXPLOITDB - DEPENDABOT - " + GLOBAL_EXPLOITDB[i] + " EXIST !")				
		}
		
	}

}

type GithubRepoPageInfo struct {
	HasNextPage bool `json:"hasNextPage"`
	EndCursor string `json:"endCursor"`
}

type GithubRepoNodes struct {
	Name string `json:"name"`
}

type GithubRepoData struct {
	Nodes []GithubRepoNodes `json:"nodes"`
	PageInfo GithubRepoPageInfo `json:"pageInfo"`
}
type GithubReposData struct {
	Repository GithubRepoData `json:"repositories"`
}
type GithubRepoOrgData struct {
	User GithubReposData `json:"organization"`
}

type GithubRepoGraphQL struct {
	Data GithubRepoOrgData `json:"data"`
}

type GithubRepo struct {
	Repos []string
}


var githubrepos GithubRepo

func initialGenerateGithubGraphQLRepoCall() (bool, string) {
	fmt.Println("initialGenerateGithubGraphQLRepoCall...")
  	method := "POST"

  	payload := strings.NewReader("{\"query\":\"query { \\r\\n  organization(login: \\\"$org\\\") {\\r\\n    repositories(first: 100) {\\r\\n      totalCount\\r\\n      nodes {\\r\\n        name\\r\\n      }\\r\\n      pageInfo {\\r\\n        hasNextPage\\r\\n        endCursor\\r\\n      }\\r\\n    }\\r\\n  }\\r\\n\\r\\n}\",\"variables\":{}}")

  	client := &http.Client {}

  	req, err := http.NewRequest(method, GLOBAL_GH_API_URL, payload)
  	if err != nil {
    	fmt.Println(err)
  	}
  
  	req.Header.Add("Accept", "application/vnd.github.hawkgirl-preview+json")
  	req.Header.Add("Authorization", "Bearer " + GLOBAL_GH_API_TOKEN)
  	req.Header.Add("Content-Type", "application/json")

  	res, err := client.Do(req)
  	if err != nil {
    	fmt.Println(err)
  	}
  	defer res.Body.Close()

  	body, err := ioutil.ReadAll(res.Body)
  	if err != nil {
    	fmt.Println(err)
  	}

  	var data GithubRepoGraphQL
  	json.Unmarshal(body, &data)

	if len(data.Data.User.Repository.Nodes) > 0 {
  		for i := 0; i < len(data.Data.User.Repository.Nodes); i++ {
  			githubrepos.Repos = append( githubrepos.Repos, data.Data.User.Repository.Nodes[i].Name)
		}
  	
  	} 
	
  	return data.Data.User.Repository.PageInfo.HasNextPage, data.Data.User.Repository.PageInfo.EndCursor
}

func generateGithubGraphQLRepoCall(hasNextPage bool, endCursor string) {
	fmt.Println("generateGithubGraphQLRepoCall..")
	if hasNextPage {

		time.Sleep(2 * time.Second)
		fmt.Println("Making REPO API call")

	  	method := "POST"
		payload := strings.NewReader("{\"query\":\"query { \\r\\n  organization(login: \\\"$org\\\") {\\r\\n    repositories(first: 100, after:\\\"" + endCursor + "\\\") {\\r\\n      totalCount\\r\\n      nodes {\\r\\n        name\\r\\n      }\\r\\n      pageInfo {\\r\\n        hasNextPage\\r\\n        endCursor\\r\\n      }\\r\\n    }\\r\\n  }\\r\\n\\r\\n}\",\"variables\":{}}")

		client := &http.Client {}
		req, err := http.NewRequest(method, GLOBAL_GH_API_URL, payload)

		if err != nil {
			fmt.Println(err)
		}
		req.Header.Add("Accept", "application/vnd.github.hawkgirl-preview+json")
		req.Header.Add("Authorization", "Bearer " + GLOBAL_GH_API_TOKEN)
		req.Header.Add("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
		}

		var data GithubRepoGraphQL
		json.Unmarshal(body, &data) 


		if len(data.Data.User.Repository.Nodes) > 0 {
			for i := 0; i < len(data.Data.User.Repository.Nodes); i++ {
		 		githubrepos.Repos = append( githubrepos.Repos, data.Data.User.Repository.Nodes[i].Name)
			}
		  	
		} 	

		//recursive call
		generateGithubGraphQLRepoCall( data.Data.User.Repository.PageInfo.HasNextPage, data.Data.User.Repository.PageInfo.EndCursor)
	}

}

func runDependabotScan() {
	repoHasNextPage, repoEndCursor := initialGenerateGithubGraphQLRepoCall()
	generateGithubGraphQLRepoCall(repoHasNextPage, repoEndCursor)

		for i := 0; i < len(githubrepos.Repos); i++ {
			dependabotHasNextPage, dependabotEndCursor := initialGenerateGithubGraphQLDependabotCall(githubrepos.Repos[i])
			generateGithubGraphQLDependabotCall(githubrepos.Repos[i], dependabotHasNextPage, dependabotEndCursor)
		}
	
	file, _ := json.MarshalIndent(githubdependabotalerts, "", " ")
	_ = ioutil.WriteFile("dependabot_findings.json", file, 0644)

}

func createDependabotCVEMap() {
	fmt.Println("createDependabotCVEMap..")
	jsonFile, err := os.Open("./dependabot_findings.json")
	// if we os.Open returns an error then handle it
	if err != nil {
	fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we initialize our Users array
	var findings GithubDependabot
	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	json.Unmarshal(byteValue, &findings)

	for i := 0; i < len(findings.Vulnerabilities); i++ {
		if len(findings.Vulnerabilities[i].SecurityAdvisory.Identifiers) > 1 {
				_, ok := GLOBAL_DEPENDABOT_CVE_MAP[findings.Vulnerabilities[i].SecurityAdvisory.Identifiers[1].Value]
				if !ok {
					GLOBAL_DEPENDABOT_CVE_MAP[findings.Vulnerabilities[i].SecurityAdvisory.Identifiers[1].Value] = 1
				}
		}
	}

}

func dependabotFindings(w http.ResponseWriter, req *http.Request) {
	jsonFile, err := os.Open("./dependabot_findings.json")
	// if we os.Open returns an error then handle it
	if err != nil {
	fmt.Println(err)
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we initialize our Users array
	var findings GithubDependabot
	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	json.Unmarshal(byteValue, &findings)


	
	jsonResp, err := json.Marshal(findings)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
	return
}

type GithubDependabotPackage struct {
	Name string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type GithubDependabotAdvisory struct {
	Description string `json:"description"`
}
type GithubDependabotSecVuln struct {
	Package GithubDependabotPackage `json:"package"`
	Severity string `json:"severity"`
	Advisory GithubDependabotAdvisory `json:"advisory"`
}

type GithubDependabotIdentifier struct {
	TypeOfIdentifier string `json:"type"` //CVE or GHSA
	Value string `json:"value"` // CVE-####-#####
}
type GithubDependabotSecAdvisory struct {
	Identifiers []GithubDependabotIdentifier `json:"identifiers"`
	Classification string `json:"classification`
	CVSScore GithubDependabotCVSS `json:"cvss"`
	PublishedAt string `json:"publishedAt"`
}

type GithubDependabotCVSS struct {
	Score float64 `json:"score"`
	Vector string `json:"vectorString"`
}
type GithubDependabotNode struct {
	Repository string 
	State string `json:"state"`
	ManifestFileName string `json:"vulnerableManifestFilename"`
	ManifestFilePath string `json:"vulnerableManifestPath"`
	VulnRequirements string `json:"vulnerableRequirements"`
	SecurityVulnerability GithubDependabotSecVuln `json:"securityVulnerability"`
	SecurityAdvisory GithubDependabotSecAdvisory `json:"securityAdvisory"`
	CreatedAt string `json:"createdAt"`
}

type GithubDependabotPageInfo struct {
	HasNextPage bool `json:"hasNextPage"`
	EndCursor string `json:"endCursor"`
}

type GithubDependabotVulnerability struct {
	Nodes []GithubDependabotNode `json:"nodes"`	
	PageInfo GithubDependabotPageInfo `json:"pageInfo"`
}

type GithubDependabotData struct {
	VulnerabilityAlerts GithubDependabotVulnerability `json:"vulnerabilityAlerts"`
}
type GithubDependabotRepoData struct {
	Repository GithubDependabotData `json:"repository"`
}

type GithubDependabotGraphQL struct {
	Data GithubDependabotRepoData `json:"data"`
}

type GithubDependabot struct {
	Vulnerabilities []GithubDependabotNode
}
var githubdependabotalerts GithubDependabot

func initialGenerateGithubGraphQLDependabotCall(repo string)  (bool, string){
	fmt.Println("initialGenerateGithubGraphQLDependabotCall..")
	fmt.Println(repo)
	
  	method := "POST"

  	payload := strings.NewReader("{\"query\":\"query { \\r\\n    repository(name: \\\"" + repo + "\\\", owner: \\\"$org\\\") {\\r\\n        vulnerabilityAlerts(first: 100) {\\r\\n            nodes {\\r\\n                state \\r\\n                createdAt \\r\\n  vulnerableManifestFilename \\r\\n                vulnerableManifestPath \\r\\n                vulnerableRequirements \\r\\n                securityAdvisory{\\r\\n                    identifiers {\\r\\n                        type \\r\\n                        value\\r\\n                    }\\r\\n classification \\r\\n  cvss {\\r\\n score\\r\\n vectorString \\r\\n } publishedAt \\r\\n             }\\r\\n                securityVulnerability {\\r\\n                    package {\\r\\n                        name\\r\\n                        ecosystem\\r\\n                    }\\r\\n                    severity \\r\\n              \\r\\n                    advisory {\\r\\n                        description\\r\\n                    }\\r\\n                }\\r\\n            }\\r\\n            pageInfo {\\r\\n                hasNextPage \\r\\n                endCursor\\r\\n            }\\r\\n        }\\r\\n    }\\r\\n}\",\"variables\":{}}")

  	client := &http.Client {}
  	req, err := http.NewRequest(method, GLOBAL_GH_API_URL, payload)

  	if err != nil {
    	fmt.Println(err)
  	}
  	req.Header.Add("Accept", "application/vnd.github.hawkgirl-preview+json")
  	req.Header.Add("Authorization", "Bearer " + GLOBAL_GH_API_TOKEN)
  	req.Header.Add("Content-Type", "application/json")

  	res, err := client.Do(req)
  	if err != nil {
    	fmt.Println(err)
  	}
  	defer res.Body.Close()

  	body, err := ioutil.ReadAll(res.Body)
  	if err != nil {
    	fmt.Println(err)
 	}

 	var data GithubDependabotGraphQL
	json.Unmarshal(body, &data) 

	if len(data.Data.Repository.VulnerabilityAlerts.Nodes) > 0 {
		for i := 0; i < len(data.Data.Repository.VulnerabilityAlerts.Nodes); i++ {
			data.Data.Repository.VulnerabilityAlerts.Nodes[i].Repository = repo
	 		githubdependabotalerts.Vulnerabilities = append( githubdependabotalerts.Vulnerabilities, data.Data.Repository.VulnerabilityAlerts.Nodes[i])
	  	}
	  	
	} 	


	return  data.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage, data.Data.Repository.VulnerabilityAlerts.PageInfo.EndCursor
}
func generateGithubGraphQLDependabotCall(repo string, hasNextPage bool, endCursor string) {
	fmt.Println("generateGithubGraphQLDependabotCall..")
	fmt.Println(repo)
	if hasNextPage{
		time.Sleep(2 * time.Second)
		fmt.Println("Making DEPENDABOT API call")

	  	method := "POST"

	  	payload := strings.NewReader("{\"query\":\"query { \\r\\n    repository(name: \\\"" + repo + "\\\", owner: \\\"$org\\\") {\\r\\n        vulnerabilityAlerts(first: 100, after:\\\"" + endCursor + "\\\") {\\r\\n            nodes {\\r\\n                state \\r\\n           createdAt \\r\\n     vulnerableManifestFilename \\r\\n                vulnerableManifestPath \\r\\n                vulnerableRequirements \\r\\n                securityAdvisory{\\r\\n                    identifiers {\\r\\n                        type \\r\\n                        value\\r\\n                   }\\r\\n      classification \\r\\n  cvss {\\r\\n score\\r\\n vectorString \\r\\n } publishedAt \\r\\n           }\\r\\n                securityVulnerability {\\r\\n                    package {\\r\\n                        name\\r\\n                        ecosystem\\r\\n                    }\\r\\n                    severity \\r\\n              \\r\\n                    advisory {\\r\\n                        description\\r\\n                    }\\r\\n                }\\r\\n            }\\r\\n            pageInfo {\\r\\n                hasNextPage \\r\\n                endCursor\\r\\n            }\\r\\n        }\\r\\n    }\\r\\n}\",\"variables\":{}}")

	  	client := &http.Client {}
	  	req, err := http.NewRequest(method, GLOBAL_GH_API_URL, payload)

	  	if err != nil {
	    	fmt.Println(err)
	  	}
	  	req.Header.Add("Accept", "application/vnd.github.hawkgirl-preview+json")
	  	req.Header.Add("Authorization", "Bearer " + GLOBAL_GH_API_TOKEN)
	  	req.Header.Add("Content-Type", "application/json")

	  	res, err := client.Do(req)
	  	if err != nil {
	    	fmt.Println(err)
	  	}
	  	defer res.Body.Close()

	  	body, err := ioutil.ReadAll(res.Body)
	  	if err != nil {
	    	fmt.Println(err)
	 	}

	 	var data GithubDependabotGraphQL
		json.Unmarshal(body, &data) 

		if len(data.Data.Repository.VulnerabilityAlerts.Nodes) > 0 {
			for i := 0; i < len(data.Data.Repository.VulnerabilityAlerts.Nodes); i++ {
				data.Data.Repository.VulnerabilityAlerts.Nodes[i].Repository = repo
		 		githubdependabotalerts.Vulnerabilities = append( githubdependabotalerts.Vulnerabilities, data.Data.Repository.VulnerabilityAlerts.Nodes[i])
		  	}
		  	
		} 	

		//recursive call
		generateGithubGraphQLDependabotCall( repo, data.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage, data.Data.Repository.VulnerabilityAlerts.PageInfo.EndCursor)

		
	}
}


var GLOBAL_EXPLOITDB []string

func setExploitDBMapping() {
	fmt.Println("setExploitDBMapping..")
    resp, err := http.Get(GLOBAL_EXPLOIT_DB_MAPPING_URL)

    if err != nil {
        log.Fatal(err)
    }

    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        log.Fatalf("failed to fetch data: %d %s", resp.StatusCode, resp.Status)
    }

    doc, err := goquery.NewDocumentFromReader(resp.Body)

    if err != nil {
        log.Fatal(err)
    }

	doc.Find("table").Each(func(index int, tablehtml *goquery.Selection) {
		if index == 3 {
			tablehtml.Find("tr").Each(func(indextr int, rowhtml *goquery.Selection) {
			
				rowhtml.Find("td").Each(func(indexth int, tablecell *goquery.Selection) {
					if indexth == 1 {
						var splits = strings.Split(strings.TrimSpace(tablecell.Text()), " ")
						for i := 0; i < len(splits); i++ {
							GLOBAL_EXPLOITDB = append(GLOBAL_EXPLOITDB, splits[i])
						}
					}
				})
				
			})
		}
	
	})

	
}


func fetchCISAVulnerabilityFeed(url string) (*CISA, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch vulnerability feed: %v", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vulnerabilityFeed CISA
	err = json.Unmarshal(body, &vulnerabilityFeed)
	if err != nil {
		return nil, err
	}

	return &vulnerabilityFeed, nil
}