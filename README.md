
<p align="center">
    <img src="https://github.com/user-attachments/assets/2598e2c1-5f41-4f8e-8dd5-c9b3057ddb5b" width="250" alt="Cosca logo">
</p>

# Cosca

** Cosca (Combo Scanner) is an Application Security automation tool that invokes third-party scanners and processes outputs in a one-liner command. **

# TL;DR
```console
python3 cosca.py -t https://ginandjuice.shop bkimminich/juice-shop:latest https://github.com/juice-shop/juice-shop -o pdf zip defectdojo
```


# Introduction

Cosca takes advantage of appsec scanners that offer their official docker version. It identifies each type of target and invokes the appropiate scanner.
Possible target types include: website, API, directory, github repository, container. 
A combination of scanners and types of targets for a particular purpose are called combos and are defined in the file combos.json that can be customized. 
Implemented scanners so far: 
- Kics (IaC)
- CycloneDX (SBOM generation and scanning)
- Syft + Grype (SBOM generation and scanning)
- Semgrep (SAST)
- ZAP (API, website)
- Dastardly (websites)
- Trivy (containers)
- Trufflehog (Secrets)


# Characteristics

- Docker based
- Simple
- Scalable, add scanners and custom output handlers
- Customizable, define combos and paremetrize scanners according to your needs.
- Based on niche scanners

# Why cosca?

- Provides a standard method to scan all your assets, no matter if they are directories, repositories, containers, websites or APIs.
- Docker based scanners ensure you are always using the latest version of the scanners from the official registries.
- Choose how to process the outputs: console, zip file, json reports, PDFs or import into DefectDojo.
- Can be invoked from your local environment, from a CI/CD or from any other environment supporting docker.
- Easily add new combos, scanners and custom output handlers.

# Possible use cases
- Generate SBOM, scan dependencies and source code of a project in a local directory.
- Scan source code, docker images and the deployed website of a web project and check the results in DefectDojo immediately.
- Scan for leaked secrets in source code with --quiet and pipe the output to jq to take action.
- Have a brief understanding of the security debt of an outdated project. 
- Scan all the assets involved in a deployment during the CI/CD and attach the report or even block the pipeline if the expected criteria is not met.
- Check 3rd party code to show up the evident associated risks.
- Common Vulnerability Management duties. Scan, share results, rescan, compare, inform.



## FAQS

- Why inluded 2 different SBOM scanners (Grype and CdxGen)
- Feature 2
- Feature 3
