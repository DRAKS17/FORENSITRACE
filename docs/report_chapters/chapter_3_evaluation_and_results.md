# Chapter 3: Evaluation Experiment and Empirical Results

**Author:** DAKSH  
**Reviewer:** AKASH

## 3.1 Evaluation Objectives
The evaluation phase addresses two critical research questions:
1. **Investigative Efficiency:** Does ForensiTrace reduce the time required to comprehend a multi-stage intrusion sequence compared to traditional Windows Event Viewer analysis?
2. **Resource Footprint:** Does the background endpoint agent satisfy the "minimal overhead" requirement (<2% CPU, <35 MB RAM)?

## 3.2 Human-Subject Comprehension Experiment
An empirical study was conducted with 8 independent computer science undergraduate participants. The experiment utilized a within-subject, counterbalanced 2x2 design alternating between Scenario A and Scenario A' to neutralize difficulty and ordering effects.

### 3.2.1 Quantitative Results

| Metric | Windows Event Viewer (Control) | ForensiTrace Dashboard (Treatment) | Difference / Improvement |
| :--- | :---: | :---: | :---: |
| **Median Completion Time** | 367.5 seconds | 66.5 seconds | **-81.9% Time Saved** |
| **Mean Completion Time** | 367.5 &plusmn; 49.5 s | 67.0 &plusmn; 8.2 s | **Statistically Distinct** |
| **Investigation Accuracy** | 3.0 / 5 (60.0%) | 5.0 / 5 (100.0%) | **+40.0% Higher Accuracy** |
| **Error Rate (Sequence Order)** | 37.5% incorrect | 0.0% incorrect | **Zero Ordering Errors** |

### 3.2.2 Qualitative Findings
Participants reported severe cognitive fatigue when filtering raw Event Viewer logs due to non-correlated entries and unfamiliar Event IDs. Conversely, ForensiTrace's unified timeline and explicit evidence provenance allowed immediate identification of the attacker's full path (USB insertion &rarr; file staging &rarr; execution &rarr; log erasure).

## 3.3 Agent Performance Benchmark
Resource consumption was profiled on Windows 11 during both idle operation and active file-copy bursts (50 rapid file creations):

| Operational State | Average CPU (%) | Peak CPU (%) | Average RAM (MB) | Peak RAM (MB) |
| :--- | :---: | :---: | :---: | :---: |
| **Idle Baseline** | 0.42% | 0.85% | 23.4 MB | 25.1 MB |
| **Active Burst (50 writes)** | 1.15% | 1.80% | 26.8 MB | 29.4 MB |

These figures substantiate the project's expected outcomes, demonstrating that ForensiTrace operates with minimal footprint and zero perceptible system degradation.
