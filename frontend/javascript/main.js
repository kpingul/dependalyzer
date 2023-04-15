getDependabot();

//TOP LEVEL
let GLOBAL_VAR = {
  API: {
    dependabot: "http://127.0.0.1:8090/api/v1/github/dependabot/all"
  },
  Jan: "Jan",
  Feb: "Feb",
  Mar: "Mar",
  Apr: "Apr",
  May: "May",
  Jun: "Jun",
  Categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
  vulns: {
    Critical: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    High: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    Medium: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    Low: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
  },
  closedVulns: {
    Critical: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    High: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    Medium: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
    Low: {
      Jan: 0,
      Feb: 0,
      Mar: 0,
      Apr: 0,
      May: 0,
      Jun: 0,
      Total: 0,
    },
  },
};


Highcharts.setOptions({
  colors: [
    "#072448",
    "#54D2D2",
    "#009eff",
    "#F8AA4B",
    "#C6BEBD",
    "#00d9e9",
    "#00ffff",
  ],
});


let tabComponent = new Vue({
  el: "#tabComponent",
  data: {
    dependency: false,
  },
  methods: {
    setDependency(state) {
  
      $(".dependency-mgmt").removeClass("hidden");
      $(".dependency-mgmt").addClass("show");
      Vue.set(tabComponent, "dependency", state);
    },
  },
});



let dependencyMgmtComponent = new Vue({
  el: "#dependencyMgmtComponent",
  data: {
    totalRepo: 0,
    totalVuln: 0,
    criticalVuln: 0,
    highVuln: 0,
    medVuln: 0,
    lowVuln: 0,
    repoCount: 0,
  },
});

let dependabotFindingsComponent = new Vue({
  el: "#dependabotFindings",
  data: {
    rows: [],
    rows_snyk: [],
  },
  methods: {
    checkForSeverity(state) {
      if (state.toUpperCase() == "CRITICAL") {
        return (
          '<span class="bg-danger" style="padding: 6px; color: white; border-radius: 10px; width: 120px; font-size: 12px; display: block; height: 32px; text-align:center;">' +
          state +
          "</span>"
        );
      }
      if (state.toUpperCase() == "HIGH") {
        return (
          '<span style="padding: 6px; color: white; border-radius: 10px; width: 120px; font-size: 12px; display: block; height: 32px; text-align:center; background: #ff6616 !important">' +
          state +
          "</span>"
        );
      }
      if (state.toUpperCase() == "MODERATE") {
        return (
          '<span  style="padding: 6px; color: white; border-radius: 10px; width: 120px; font-size: 12px; display: block; height: 32px; text-align:center; background: #ffc651 !important;">' +
          state +
          "</span>"
        );
      }
      if (state.toUpperCase() == "MEDIUM") {
        return (
          '<span  style="padding: 6px; color: white; border-radius: 10px; width: 120px; font-size: 12px; display: block; height: 32px; text-align:center; background: #ffc651 !important;">' +
          state +
          "</span>"
        );
      }
      if (state.toUpperCase() == "LOW") {
        return (
          '<span  style="padding: 6px; color: white; border-radius: 10px; width: 120px; font-size: 12px; display: block; height: 32px; text-align:center; background: rgb(246 204 0);">' +
          state +
          "</span>"
        );
      }
    },
  },
});
let GLOBAL_DEPENDABOT_VULNS = [];
function getDependabot() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      // getSnykSCA()
      // GLOBAL_DEPENDABOT_VULNS = JSON.parse(this.response).Vulnerabilities.filter((x,i) => x.state == "OPEN")
      //JJSON.parse(this.response).Vulnerabilities.filter((x,i) => x.state == "OPEN")
      let dataSet = JSON.parse(this.response).Vulnerabilities.filter(
        (x, i) => x.state == "OPEN"
      );

      console.log(dataSet)
      let totalCount = dataSet.length;
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      var cvssCategories = [
        0, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5, 7.0,
        7.5, 8.0, 8.5, 9.0, 9.5, 10.0,
      ];
      var scores = [];

      cvssCategories.forEach((item, idx) => {
        scores.push(0);
      });

      dataSet.forEach((vuln, idx) => {
        if (vuln.securityVulnerability.severity == "CRITICAL") {
          criticalCount++;
        }
        if (vuln.securityVulnerability.severity == "HIGH") {
          highCount++;
        }
        if (vuln.securityVulnerability.severity == "MODERATE") {
          mediumCount++;
        }
        if (vuln.securityVulnerability.severity == "LOW") {
          lowCount++;
        }

        var scoreIndex = null;
        cvssCategories.forEach((item, idx) => {
          if (
            vuln.securityAdvisory.cvss.score >= item &&
            vuln.securityAdvisory.cvss.score < cvssCategories[idx + 1]
          ) {
            scoreIndex = idx;
          }
          if (cvssCategories.length - 1 == idx) {
            if (
              vuln.securityAdvisory.cvss.score > cvssCategories[idx - 1] &&
              vuln.securityAdvisory.cvss.score <= cvssCategories[idx]
            ) {
              scoreIndex = idx;
            }
          }
        });
        if (scoreIndex) {
          scores[scoreIndex]++;
        }
      });

      let repositories = _.groupBy(dataSet, (item, idx) => {
        return item.Repository;
      });

      repositories = Object.keys(repositories)
        .map(function (k) {
          return { key: k, value: repositories[k] };
        })
        .sort(function (a, b) {
          return b.value.length - a.value.length;
        });

      let packages = _.groupBy(dataSet, (item, idx) => {
        return item.securityVulnerability.package.name;
      });

      packages = Object.keys(packages)
        .map(function (k) {
          return { key: k, value: packages[k] };
        })
        .sort(function (a, b) {
          return b.value.length - a.value.length;
        });

      let ecosystems = _.groupBy(dataSet, (item, idx) => {
        return item.securityVulnerability.package.ecosystem;
      });

      ecosystems = Object.keys(ecosystems)
        .map(function (k) {
          return { key: k, value: ecosystems[k] };
        })
        .sort(function (a, b) {
          return b.value.length - a.value.length;
        });

      setVulnDependabotChart("dependabot-repo", repositories);
      setVulnDependabotChart("dependabot-packages", packages);
      setVulnDependabotChart("dependabot-ecosystem", ecosystems);

      setDependabotSeverityChart(
        criticalCount,
        highCount,
        mediumCount,
        lowCount
      );
      setDependabotVulnCVSSChart(cvssCategories, scores);

      Vue.set(
        dependencyMgmtComponent,
        "totalRepo",
        Object.keys(repositories).length
      );
      Vue.set(dependencyMgmtComponent, "totalVuln", totalCount);
      Vue.set(dependencyMgmtComponent, "criticalVuln", criticalCount);
      Vue.set(dependencyMgmtComponent, "highVuln", highCount);
      Vue.set(dependencyMgmtComponent, "medVuln", mediumCount);
      Vue.set(dependencyMgmtComponent, "lowVuln", lowCount);
      // Vue.set(dependabotFindingsComponent, 'rows', _.sortBy(dataSet, (obj) => obj.createdAt ).reverse() )
      // Vue.set(dependabotFindingsComponent, 'rows', _.sortBy(dataSet.filter( (data,idx) => data.securityVulnerability.package.ecosystem == "GO"), (obj) => obj.securityVulnerability.package.name ))
      Vue.set(
        dependabotFindingsComponent,
        "rows",
        _.sortBy(dataSet, (obj) => obj.securityVulnerability.severity)
      );
      // Vue.set(dependabotFindingsComponent, 'rows', _.sortBy(dataSet, (obj) => obj.securityVulnerability.package.name ))
      // Vue.set(
      //   dependabotFindingsComponent,
      //   "rows",
      //   _.sortBy(dataSet, (obj) => obj.Repository)
      // );
    }
  };
  xhttp.open("GET", GLOBAL_VAR.API.dependabot, true);
  xhttp.send();
}
function setVulnDependabotChart(titleOfChart, data) {
  console.log("setVulnDependabotRepoChart..");
  let categories = [];
  let critical = [];
  let high = [];
  let med = [];
  let low = [];
  let criticalCount = 0;
  let highCount = 0;
  let medCount = 0;
  let lowCount = 0;
  Object.keys(data).forEach(function (key, index) {
    if (index <= 9) {
      categories.push(data[key].key);
      data[key].value.forEach((vuln, idx) => {
        if (vuln.securityVulnerability.severity == "CRITICAL") {
          criticalCount = criticalCount + 1;
        }
        if (vuln.securityVulnerability.severity == "HIGH") {
          highCount = highCount + 1;
        }
        if (vuln.securityVulnerability.severity == "MODERATE") {
          medCount = medCount + 1;
        }
        if (vuln.securityVulnerability.severity == "LOW") {
          lowCount = lowCount + 1;
        }
      });

      critical.push(criticalCount);
      high.push(highCount);
      med.push(medCount);
      low.push(lowCount);
      criticalCount = 0;
      highCount = 0;
      medCount = 0;
      lowCount = 0;
    }
  });

  Highcharts.chart(titleOfChart, {
    chart: {
      type: "bar",
      backgroundColor: "transparent",
    },
    title: {
      text: "",
    },
    xAxis: {
      categories: categories,
    },
    yAxis: {
      min: 0,
      title: {
        text: "",
      },
    },
    legend: {
      reversed: true,
    },
    credits: {
      enabled: false,
    },
    plotOptions: {
      series: {
        stacking: "normal",
      },
    },
    series: [
      {
        name: "Critical",
        data: critical,
        color: "#dc3545",
      },
      {
        name: "High",
        data: high,
        color: "#ff6616",
      },
      {
        name: "Medium",
        data: med,
        color: "#f6a600",
      },
      {
        name: "Low",
        data: low,
        color: "#f6dd00",
      },
    ],
  });
}

function setDependabotSeverityChart(
  criticalCount,
  highCount,
  medCount,
  lowCount
) {
  console.log("setDependabotSeverityChart..");
  let graphData = [
    {
      name: "Critical",
      y: criticalCount,
      color: "#dc3545",
    },
    {
      name: "High",
      y: highCount,
      color: "#ff6616",
    },
    {
      name: "Medium",
      y: medCount,
      color: "#f6a600",
    },
    {
      name: "Low",
      y: lowCount,
      color: "#f6dd00",
    },
  ];

  Highcharts.chart("dependabot-severity", {
    chart: {
      plotBackgroundColor: null,
      plotBorderWidth: null,
      plotShadow: false,
      backgroundColor: "transparent",
      type: "pie",
      events: {
        render: function () {
          var series = this.series[0],
            seriesCenter = series.center,
            x = seriesCenter[0] + this.plotLeft,
            y = seriesCenter[1] + this.plotTop,
            text = series.total.toString(),
            fontMetrics = this.renderer.fontMetrics(1);
          if (!this.customTitle) {
            this.customTitle = this.renderer
              .text(text, null, null, true)
              .css({
                transform: "translate(-50%)",
                fontSize: "30px",
              })
              .add();
          }
          this.customTitle.attr({
            x,
            y: y + fontMetrics.f / 2,
          });
        },
      },
    },
    title: {
      text: "",
    },
    tooltip: {
      pointFormat: "{series.name} <b>{point.y}</b>",
    },
    accessibility: {
      point: {
        valueSuffix: "%",
      },
    },
    plotOptions: {
      pie: {
        allowPointSelect: true,
        cursor: "pointer",
        dataLabels: {
          enabled: false,
        },
        showInLegend: true,
      },
    },
    legend: {
      layout: "vertical",
      align: "right",
      verticalAlign: "top",
      itemMarginTop: 5,
      itemMarginBottom: 5,
      x: -50,
      y: 70,
      itemStyle: {
        fontSize: "14px",
      },
    },
    credits: {
      enabled: false,
    },
    exporting: { enabled: false },
    series: [
      {
        name: "",
        colorByPoint: true,
        data: graphData,
        size: "100%",
        innerSize: "75%",
      },
    ],
  });
}

function setDependabotVulnCVSSChart(categories, scores) {
  console.log("setDependabotVulnCVSSChart..");

  Highcharts.chart("dependabot-cvss", {
    chart: {
      type: "line",
      backgroundColor: "transparent",
      marginBottom: 65,
    },
    title: {
      text: "",
    },
    xAxis: {
      categories: categories,
      crosshair: true,
    },
    legend: {
      squareSymbol: true,
    },
    yAxis: {
      min: 0,
      title: {
        text: "",
      },
    },
    tooltip: {
      headerFormat:
        '<span style="font-size:10px">CVSS Score:{point.key}</span><table>',
      pointFormat: '<td style="padding:0">Total:<b>{point.y}</b></td></tr>',
      footerFormat: "</table>",
      shared: true,
      useHTML: true,
    },
    plotOptions: {
      series: {
        groupPadding: 0,
        pointPlacement: "on",
        marker: {
          enabled: false,
        },
      },
    },
    credits: {
      enabled: false,
    },
    series: [
      {
        name: "Score",
        data: scores,
        marker: {
          enabled: false,
        },
      },
    ],
  });
}





