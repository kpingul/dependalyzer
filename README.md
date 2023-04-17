# dependalyzer

## Purpose

One of the biggest problems with dependabot is that you can't get an aggregate view of all the vulnerable dependencies across all your repositories. Teams would have to manually visit each repository and view the findings one by one. At the end of the day, this does not scale. The goal of this project is to solve that. This project aggregates all the dependabot findings using GitHub's GraphQL API, scans across the entire organization's repositories, and use data visualizations to help teams understand and  prioritize the overall vulnerable dependencies across their organization.


![dependalyzer-poc](https://user-images.githubusercontent.com/11414669/226249186-43c4e6bc-bd5e-4432-9a87-1767b344a4c4.png)
