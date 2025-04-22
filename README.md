
<p align="center">
    <img src="https://github.com/user-attachments/assets/98a77ea1-7904-4e2b-a362-f87b920ef82c" width="250" alt="Cosca logo">
</p>

# Cosca

Cosca (Combo Scanner) is an Application Security automation tool that invokes third-party scanners and processes outputs in a one-liner command.

# TL;DR
```text
# Scan website, Docker image and repo. Write the summary in a PDF and zip the reports, all in one shot:

python3 cosca.py \
  -t https://ginandjuice.shop \
     bkimminich/juice-shop:latest \
     https://github.com/juice-shop/juice-shop \
  -o pdf zip
```

![Demo](https://github.com/jbeduino/cosca/releases/download/untagged-9733af0a0ebbc760195e/demo.gif)


# Introduction

Cosca takes advantage of appsec scanners that offer their official docker version. It identifies each type of target and invokes the appropiate scanners.
Possible target types included from scratch: directory, website, API, Github repository and docker image. 
A combination of scanners and types of targets for a particular purpose are called combos and are defined in the file combos.json that can be customized. 
Implemented scanners so far: 
- Kics (IaC)
- CycloneDX (SBOM generation and scanning)
- Syft + Grype (SBOM generation and scanning)
- Semgrep (SAST)
- ZAP (API, website)
- Dastardly (website)
- Trivy (containers)
- Trufflehog (secrets)


## Prerequisites

- [Docker](https://www.docker.com/) (v25+ recommended)
- [Python 3](https://www.python.org/downloads/) (v3.10+ recommended)


## Characteristics

- 🐳 **Docker-based** – easy to run and isolate
- ⚙️ **Simple** – minimal setup, no fluff
- 📈 **Scalable** – add new scanners and output handlers with ease
- 🎛️ **Customizable** – define scan combos and parameterize tools to fit your workflow
- 🧪 **Built on niche scanners** – leverages specialized tools for targeted analysis


# Why Cosca?

- 🔍 Unified scanning – Scan any type of asset with a consistent approach: directories, repositories, containers, websites, or APIs.
- 🐳 Always up-to-date – Docker-based scanners ensure you're using the latest official versions straight from trusted registries.
- 🧾 Flexible output handling – Choose how you want the results: console output, ZIP archives, JSON reports, PDFs, or even direct import into DefectDojo.
- ⚙️ Run it anywhere – Works seamlessly from your local machine, CI/CD pipelines, or any Docker-capable environment.
- 🛠️ Fully extensible – Easily add new scan combos, integrate custom scanners, or define your own output handlers.


# Use cases
- 🔧 Local project analysis – Generate an SBOM, scan dependencies, and analyze source code for any project in a local directory.
- 🌐 Full-stack scanning – Scan source code, Docker images, and the live website of a web project, and instantly review the results in DefectDojo.
- 🕵️‍♂️ Secret detection automation – Quietly scan source code for leaked secrets using --quiet and pipe the output to tools like jq for automated response.
- 📉 Assess legacy security debt – Quickly evaluate the security posture of outdated or legacy projects.
- 🚀 CI/CD integration – Scan all assets involved in a deployment during CI/CD, generate reports, and optionally block the pipeline if criteria aren’t met.
- 🧩 Third-party code review – Identify obvious risks in third-party code before integration.
- 📊 Vulnerability management workflows – Automate scanning, track results, perform rescans, compare reports over time, and communicate findings effectively.


# Step by step example

## Clone Cosca repository
```console
git clone git@github.com:jbeduino/cosca.git
```

## Create a virtual environment
```console
python3 -m venv venv
source venv/bin/activate
```
## Install dependencies
```console
pip install -r requirements.txt
```

## Clone a vulnerable project to scan
```console
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop-master
```

## Setup DefectDojo

To import the results into DefectDojo, set DEFECTDOJO_URL and DEFECTDOJO_API_KEY environment variables as a minimum. 

```console
export DEFECTDOJO_URL=https://demo.defectdojo.org
export DEFECTDOJO_API_KEY=XXXXXXX
```

You can also add more preferences: DEFECTDOJO_ENGAGEMENT_ID, DEFECTDOJO_PRODUCT_ID and DEFECTDOJO_PRODUCT_TYPE_ID. The demo site of DefectDojo can be used for tests. Log in with username admin and password 1Defectdojo@demo#appsec as stated [here](https://github.com/DefectDojo/django-DefectDojo/blob/master/README.md#quick-start-for-compose-v2) and copy the API KEY from [API V2 Section](https://demo.defectdojo.org/api/key-v2). 

⚠️ **Disclaimer:**  
Don't scan sensitive data in your tests with DefectDojo demo site.


## Scan Gin & Juice and push to DefectDojo

```text
# Scan local directory with source code, the deployed web application and a related Docker image.
python3 cosca.py
  -t /tmp/juice-shop-master 
     https://ginandjuice.shop 
     bkimminich/juice-shop:latest 
  -o pdf zip defectdojo

```

## Command explanation

Scans a local directory containing source code, a website, and a Docker image. It then generates a PDF report, a ZIP archive, and creates a DefectDojo entry with all the findings — following these steps:

1. Target identification – Detects the type of each target: directory, Docker image, website, OpenAPI, GraphQL, SOAP, or GitHub repository.

2. Combo selection – Loads the appropriate scanners based on the selected configuration in combos.json.

3. Scan execution – Runs the relevant scanners against each target.

4. Result aggregation – Collects and merges the outputs from all scanners.

5. Report generation – Creates the final deliverables: PDF report, ZIP file, and pushes findings to DefectDojo.
   
# FAQs

- Can I add another scanner?  
Yes, inherit your class from Scanner (scanner.py), and place your scanner implementation in the scanners/ folder. 

- Can I add another output handler?  
Yes, inherit your class from OutputHandler (output_handler.py), and place your output handler implementation in the output_handlers/ folder. 

- Can I define a custom combination of scanners?  
Yes, add an entry to combos.json and run Cosca with `--combo <your-combo-name>`.

- Why included 2 different SBOM scanners (Syft and CdxGen)?  
CdxGen generates CycloneDX, the de facto standard for SBOMs. In contrast, Syft offers a lightweight but more limited alternative, which, for example, does not support pyproject.toml.
