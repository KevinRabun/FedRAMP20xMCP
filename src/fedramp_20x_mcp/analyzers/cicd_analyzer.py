"""
CI/CD pipeline analyzers for FedRAMP 20x compliance.

Supports analysis of CI/CD pipeline configurations including:
- GitHub Actions workflows (.github/workflows/*.yml)
- Azure DevOps pipelines (azure-pipelines.yml, *.yml)
- GitLab CI/CD (.gitlab-ci.yml)
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class CICDAnalyzer(BaseAnalyzer):
    """
    Analyzer for CI/CD pipeline configuration files.
    
    Checks for FedRAMP 20x DevSecOps compliance in pipeline definitions.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze CI/CD pipeline configuration for FedRAMP 20x compliance.
        
        Args:
            code: Pipeline configuration content (YAML/JSON)
            file_path: Path to the pipeline file
            
        Returns:
            AnalysisResult with findings
        """
        self.result = AnalysisResult()
        self.result.files_analyzed = 1
        
        # Phase 4: DevSecOps Automation
        self._check_change_management(code, file_path)
        self._check_deployment_procedures(code, file_path)
        self._check_ci_cd_testing(code, file_path)
        self._check_vulnerability_scanning(code, file_path)
        self._check_security_remediation(code, file_path)
        self._check_evidence_collection(code, file_path)
        
        return self.result
    
    def _check_change_management(self, code: str, file_path: str) -> None:
        """Check for change management automation (KSI-CMT-01)."""
        # Check for PR/MR requirements
        has_pr_triggers = bool(re.search(r"(pull_request|merge_request|pullRequest)", code))
        has_required_reviews = bool(re.search(r"(required.*review|approvers|reviewers)", code, re.IGNORECASE))
        has_branch_protection = bool(re.search(r"(protected.*branch|branch.*protection|main|master)", code))
        
        if not has_pr_triggers:
            line_num = self.get_line_number(code, "on:") or self.get_line_number(code, "trigger:")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.HIGH,
                title="Pipeline missing pull request triggers",
                description="CI/CD pipeline doesn't trigger on pull requests. FedRAMP 20x requires all changes to go through pull request review process.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure PR triggers:\n```yaml\n# GitHub Actions\non:\n  pull_request:\n    branches: [main, develop]\n    types: [opened, synchronize, reopened]\n  push:\n    branches: [main]\n\n# Azure Pipelines\ntrigger:\n  branches:\n    include: [main]\npr:\n  branches:\n    include: [main, develop]\n```\nSource: Azure Well-Architected Framework - Operational Excellence (https://learn.microsoft.com/azure/well-architected/operational-excellence/)"
            ))
        else:
            line_num = self.get_line_number(code, "pull_request") or self.get_line_number(code, "pullRequest")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.INFO,
                title="Pull request triggers configured",
                description="Pipeline includes pull request validation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure branch protection rules are enabled in repository settings.",
                good_practice=True
            ))
        
        if not has_required_reviews and "pull_request" in code.lower():
            line_num = self.get_line_number(code, "pull_request") or 1
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.MEDIUM,
                title="No required reviewers configured",
                description="Pull request workflow doesn't enforce required reviews. FedRAMP 20x requires peer review for all changes.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure required reviewers in repository settings:\n- GitHub: Settings → Branches → Branch protection rules → Require pull request reviews\n- Azure DevOps: Project Settings → Repositories → Policies → Require minimum number of reviewers\n\nMinimum recommended: 1-2 reviewers for all changes to protected branches"
            ))
    
    def _check_deployment_procedures(self, code: str, file_path: str) -> None:
        """Check for deployment procedures and gates (KSI-CMT-02)."""
        # Check for deployment jobs
        has_deployment = bool(re.search(r"(deploy|deployment|release)", code, re.IGNORECASE))
        has_approval_gates = bool(re.search(r"(approval|gate|environment|manual)", code, re.IGNORECASE))
        has_rollback = bool(re.search(r"(rollback|revert|previous.*version)", code, re.IGNORECASE))
        
        if has_deployment:
            if not has_approval_gates:
                line_num = self.get_line_number(code, "deploy") or self.get_line_number(code, "deployment")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-02",
                    severity=Severity.HIGH,
                    title="Deployment without approval gates",
                    description="Deployment jobs lack manual approval requirements. FedRAMP 20x requires controlled deployment processes with approval workflows.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure deployment approval gates:\n```yaml\n# GitHub Actions\njobs:\n  deploy-production:\n    runs-on: ubuntu-latest\n    environment:\n      name: production\n      url: https://prod.example.com\n    # Requires environment protection rules with required reviewers\n    steps:\n      - uses: actions/checkout@v3\n      - name: Deploy\n        run: ./deploy.sh\n\n# Azure Pipelines\nstages:\n  - stage: Production\n    jobs:\n      - deployment: DeployProd\n        environment: production  # Configure approvals in Environments\n        strategy:\n          runOnce:\n            deploy:\n              steps:\n                - script: ./deploy.sh\n```\nSource: Azure CAF - Deployment strategies (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/devops-principles-and-practices)"
                ))
            else:
                line_num = self.get_line_number(code, "approval") or self.get_line_number(code, "environment")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-02",
                    severity=Severity.INFO,
                    title="Deployment approval gates configured",
                    description="Pipeline includes deployment approval requirements.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Verify environment protection rules are properly configured.",
                    good_practice=True
                ))
            
            if not has_rollback:
                line_num = self.get_line_number(code, "deploy")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-02",
                    severity=Severity.MEDIUM,
                    title="No rollback procedures defined",
                    description="Deployment jobs don't include rollback steps. FedRAMP 20x requires documented rollback procedures.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add rollback capability:\n```yaml\njobs:\n  deploy:\n    steps:\n      - name: Deploy\n        run: ./deploy.sh\n        id: deploy\n      \n      - name: Rollback on failure\n        if: failure() && steps.deploy.conclusion == 'failure'\n        run: |\n          echo 'Deployment failed, rolling back...'\n          ./rollback.sh\n          exit 1\n```"
                ))
    
    def _check_ci_cd_testing(self, code: str, file_path: str) -> None:
        """Check for automated testing in CI/CD (KSI-CMT-03)."""
        # Check for test execution
        has_unit_tests = bool(re.search(r"(pytest|jest|mocha|mvn test|dotnet test|go test|npm test)", code, re.IGNORECASE))
        has_security_scan = bool(re.search(r"(trivy|snyk|checkov|terrascan|sonarqube|codeql|semgrep)", code, re.IGNORECASE))
        has_integration_tests = bool(re.search(r"(integration.*test|e2e|end.*to.*end)", code, re.IGNORECASE))
        
        if not has_unit_tests:
            line_num = self.get_line_number(code, "steps:") or self.get_line_number(code, "jobs:")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-03",
                severity=Severity.HIGH,
                title="No unit tests in CI/CD pipeline",
                description="Pipeline doesn't execute unit tests. FedRAMP 20x requires automated testing in CI/CD pipelines.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add unit test execution:\n```yaml\n- name: Run unit tests\n  run: |\n    # Python\n    pytest tests/ --cov=src --cov-report=xml\n    \n    # Node.js\n    npm test -- --coverage\n    \n    # .NET\n    dotnet test --collect:\"XPlat Code Coverage\"\n    \n- name: Upload coverage\n  uses: codecov/codecov-action@v3\n  with:\n    files: ./coverage.xml\n```\nSource: Azure WAF - Testing strategies (https://learn.microsoft.com/azure/well-architected/operational-excellence/testing-strategy)"
            ))
        else:
            line_num = self.get_line_number(code, "test")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-03",
                severity=Severity.INFO,
                title="Unit tests configured in pipeline",
                description="Pipeline executes automated unit tests.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure test coverage meets requirements (typically 70-80%).",
                good_practice=True
            ))
        
        if not has_security_scan:
            line_num = self.get_line_number(code, "steps:") or 1
            self.add_finding(Finding(
                requirement_id="KSI-CMT-03",
                severity=Severity.HIGH,
                title="No security scanning in pipeline",
                description="Pipeline lacks security scanning tools. FedRAMP 20x requires security testing in CI/CD.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add security scanning:\n```yaml\n- name: Run Trivy vulnerability scan\n  uses: aquasecurity/trivy-action@master\n  with:\n    scan-type: 'fs'\n    severity: 'CRITICAL,HIGH'\n    exit-code: '1'  # Fail build on vulnerabilities\n\n- name: Run CodeQL analysis\n  uses: github/codeql-action/analyze@v2\n\n- name: Run Checkov IaC scan\n  run: |\n    pip install checkov\n    checkov -d . --framework bicep terraform\n```\nSource: Azure Security Benchmark (https://learn.microsoft.com/security/benchmark/azure/)"
            ))
        else:
            line_num = self.get_line_number(code, "trivy") or self.get_line_number(code, "snyk") or self.get_line_number(code, "codeql")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-03",
                severity=Severity.INFO,
                title="Security scanning integrated in pipeline",
                description="Pipeline includes automated security scanning.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure scans fail the build on critical/high severity findings.",
                good_practice=True
            ))
    
    def _check_vulnerability_scanning(self, code: str, file_path: str) -> None:
        """Check for automated vulnerability scanning (KSI-AFR-01)."""
        # Check for container scanning
        has_container_scan = bool(re.search(r"(trivy|docker.*scan|container.*scan|anchore)", code, re.IGNORECASE))
        
        # Check for IaC scanning
        has_iac_scan = bool(re.search(r"(checkov|terrascan|tfsec|kics)", code, re.IGNORECASE))
        
        # Check for SAST/DAST
        has_sast = bool(re.search(r"(sonarqube|codeql|semgrep|fortify|checkmarx)", code, re.IGNORECASE))
        has_dast = bool(re.search(r"(zap|burp|dast|dynamic.*scan)", code, re.IGNORECASE))
        
        if not has_container_scan and re.search(r"(docker|container|image)", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "docker") or self.get_line_number(code, "image")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Container images not scanned for vulnerabilities",
                description="Pipeline builds containers but doesn't scan for vulnerabilities. FedRAMP 20x requires vulnerability scanning of all artifacts.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add container vulnerability scanning:\n```yaml\n- name: Build Docker image\n  run: docker build -t myapp:${{ github.sha }} .\n\n- name: Scan image with Trivy\n  uses: aquasecurity/trivy-action@master\n  with:\n    image-ref: 'myapp:${{ github.sha }}'\n    format: 'sarif'\n    output: 'trivy-results.sarif'\n    severity: 'CRITICAL,HIGH'\n    exit-code: '1'\n\n- name: Upload scan results\n  uses: github/codeql-action/upload-sarif@v2\n  with:\n    sarif_file: 'trivy-results.sarif'\n```"
            ))
        elif has_container_scan:
            line_num = self.get_line_number(code, "trivy") or self.get_line_number(code, "scan")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.INFO,
                title="Container vulnerability scanning implemented",
                description="Pipeline scans container images for vulnerabilities.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure scan results are uploaded to security dashboard.",
                good_practice=True
            ))
        
        if not has_iac_scan and re.search(r"(\.tf|\.bicep|terraform|infrastructure)", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "terraform") or self.get_line_number(code, "bicep")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Infrastructure as Code not scanned",
                description="Pipeline deploys IaC but doesn't scan for misconfigurations. FedRAMP 20x requires IaC security scanning.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add IaC scanning:\n```yaml\n- name: Run Checkov\n  uses: bridgecrewio/checkov-action@master\n  with:\n    directory: ./infrastructure\n    framework: terraform,bicep\n    soft_fail: false\n    output_format: sarif\n    output_file_path: checkov-results.sarif\n\n- name: Upload Checkov results\n  uses: github/codeql-action/upload-sarif@v2\n  with:\n    sarif_file: checkov-results.sarif\n```"
            ))
        elif has_iac_scan:
            line_num = self.get_line_number(code, "checkov") or self.get_line_number(code, "terrascan")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.INFO,
                title="IaC security scanning implemented",
                description="Pipeline includes Infrastructure as Code security scanning.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure IaC scans fail on high/critical findings.",
                good_practice=True
            ))
        
        if not has_sast:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.MEDIUM,
                title="No SAST (Static Application Security Testing)",
                description="Pipeline lacks static code analysis for security vulnerabilities. FedRAMP 20x recommends SAST tools.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add SAST scanning:\n```yaml\n- name: Initialize CodeQL\n  uses: github/codeql-action/init@v2\n  with:\n    languages: python, javascript\n\n- name: Perform CodeQL Analysis\n  uses: github/codeql-action/analyze@v2\n```"
            ))
    
    def _check_security_remediation(self, code: str, file_path: str) -> None:
        """Check for security finding remediation automation (KSI-AFR-02)."""
        # Check for automatic issue creation
        has_issue_creation = bool(re.search(r"(create.*issue|github.*issue|jira|work.*item)", code, re.IGNORECASE))
        
        # Check for blocking on security findings
        has_security_gate = bool(re.search(r"(exit.*code.*1|fail.*on|severity.*CRITICAL)", code))
        
        if not has_issue_creation and re.search(r"(scan|test|security)", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "scan") or self.get_line_number(code, "test")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.MEDIUM,
                title="No automated ticket creation for vulnerabilities",
                description="Security scans don't automatically create tracking tickets. FedRAMP 20x requires tracking and remediation of all security findings.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add automatic issue creation:\n```yaml\n- name: Create issue for vulnerabilities\n  if: failure()\n  uses: actions/github-script@v6\n  with:\n    script: |\n      github.rest.issues.create({\n        owner: context.repo.owner,\n        repo: context.repo.repo,\n        title: 'Security vulnerabilities found in ${{ github.sha }}',\n        body: 'Security scan failed. Review scan results and remediate within SLA.',\n        labels: ['security', 'vulnerability', 'priority-high']\n      })\n```"
            ))
        elif has_issue_creation:
            line_num = self.get_line_number(code, "issue") or self.get_line_number(code, "ticket")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.INFO,
                title="Automated vulnerability tracking implemented",
                description="Pipeline creates tracking tickets for security findings.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure SLA tracking is configured for vulnerability remediation.",
                good_practice=True
            ))
        
        if not has_security_gate and re.search(r"(scan|security|vulnerability)", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "scan") or 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.HIGH,
                title="Critical vulnerabilities don't block deployment",
                description="Security scans don't fail the pipeline on critical findings. FedRAMP 20x requires blocking deployments with critical vulnerabilities.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure security gates to block deployment:\n```yaml\n- name: Security scan\n  run: |\n    trivy image myapp:latest \\\n      --severity CRITICAL,HIGH \\\n      --exit-code 1  # Fail on vulnerabilities\n    \n- name: Quality gate\n  run: |\n    # Block if security score below threshold\n    if [ $SECURITY_SCORE -lt 80 ]; then\n      echo 'Security score below threshold'\n      exit 1\n    fi\n```"
            ))
    
    def _check_evidence_collection(self, code: str, file_path: str) -> None:
        """Check for continuous evidence collection (KSI-CED-01)."""
        # Check for artifact uploads
        has_artifact_upload = bool(re.search(r"(upload.*artifact|publish|store.*evidence)", code, re.IGNORECASE))
        
        # Check for test result storage
        has_test_results = bool(re.search(r"(test.*result|junit|coverage|report)", code, re.IGNORECASE))
        
        if not has_artifact_upload and re.search(r"(test|scan|build)", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "test") or self.get_line_number(code, "build")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.MEDIUM,
                title="No automated evidence collection",
                description="Pipeline doesn't store compliance evidence. FedRAMP 20x requires automated evidence generation and storage.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure evidence collection:\n```yaml\n- name: Upload test results\n  uses: actions/upload-artifact@v3\n  with:\n    name: test-results-${{ github.sha }}\n    path: |\n      **/test-results/**\n      **/coverage/**\n      **/scan-results/**\n    retention-days: 365  # FedRAMP requires 1-year retention\n\n- name: Store evidence in compliance repository\n  run: |\n    az storage blob upload-batch \\\n      --account-name $EVIDENCE_STORAGE \\\n      --destination compliance-evidence \\\n      --source ./test-results \\\n      --pattern '*'\n```\nSource: FedRAMP 20x Continuous Evidence Collection (FRR-CED)"
            ))
        elif has_artifact_upload:
            line_num = self.get_line_number(code, "upload") or self.get_line_number(code, "artifact")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.INFO,
                title="Evidence collection configured",
                description="Pipeline collects and stores compliance evidence.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify evidence retention meets FedRAMP requirements (typically 1 year).",
                good_practice=True
            ))
        
        if not has_test_results and has_artifact_upload:
            line_num = self.get_line_number(code, "upload")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.LOW,
                title="Test results not included in evidence",
                description="Artifact uploads don't include test results. FedRAMP 20x requires comprehensive evidence including test execution records.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Include test results in evidence:\n- Unit test results (JUnit XML)\n- Code coverage reports\n- Security scan results (SARIF)\n- Integration test logs\n- Deployment verification tests"
            ))
