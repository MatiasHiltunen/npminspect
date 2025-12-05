`npm audit` can't apparently find vulnerable packages from nested deps.
![npm audit fix](report_1.png)
![npminspect audit](report_2.png)

By allowing the `npminspect` to scan the node_modules folder recursively we can find plenty of high severity vulnerability packages listed in lock-files etc.  
![npminspect audit in depth](report_3.png)

By default the npminspect also scans the dev-deps but the results were the same with flag `--include-non-runtime false` with this particular project. 

Issue is that `npm audit fix` can not, atleast by default, detect the nested vulnerabilities and this could be one of the reasons that makes the npm ecosystem delicious ground for supply-chain attacks.