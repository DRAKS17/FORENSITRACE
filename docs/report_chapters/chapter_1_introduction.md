# Chapter 1: Introduction, Problem Statement, and Objectives

**Authors:** Entire Team (Reused and expanded from project synopsis)  
**Reviewer:** PURVA

## 1.1 Introduction
Modern enterprise threat actors frequently rely on multi-stage intrusion tactics that traverse multiple host subsystems. A typical lateral staging sequence involves connecting a portable removable device, transferring unauthorized executables or scripts to the filesystem, executing the staged binary, and subsequently clearing system audit logs to hinder post-incident analysis. While Windows operating systems log discrete signals across distinct subsystems (such as Windows Event Logs, File System change journals, and Device Manager events), these telemetry streams exist in completely isolated silos.

## 1.2 Limitations of Existing Forensic Tools
Security Operations Center (SOC) analysts and forensic investigators face several fundamental challenges:
1. **Disconnected Telemetry Silos:** Standard Windows Event Viewer displays events chronologically in a flat list without semantic linkages connecting a device insertion (WMI) to a newly dropped binary (watchdog) and subsequent process creation (Event ID 4688).
2. **Cognitive Overload & Manual Stitching:** Investigators must manually cross-reference timestamps across disparate logs, leading to substantial investigative fatigue and increased error rates.
3. **Heavyweight Endpoint Overhead:** Traditional enterprise EDR (Endpoint Detection and Response) agents often introduce substantial CPU and memory overhead, making them impractical for lightweight, air-gapped, or resource-constrained endpoints.
4. **Lack of Evidence Provenance:** Many modern commercial SIEMs utilize opaque machine learning heuristics that output alert scores without explaining the exact chain of underlying raw artifacts.

## 1.3 Problem Statement
The objective of this research is to design, implement, and evaluate **ForensiTrace**: a lightweight, cross-source forensic correlation platform for Windows endpoints. ForensiTrace collects events across three critical sources (USB/Removable devices, File System operations, and Windows Event Logs), normalizes them into a unified chronological schema, anchors records within an append-only cryptographic hash chain, and executes deterministic rule-based correlation to reconstruct explainable threat narratives while maintaining an overhead under 2% CPU and 35 MB RAM.

## 1.4 Project Objectives
1. **Multi-Source Collection:** Construct asynchronous, decoupled collectors for Windows WMI volume changes, watchdog filesystem events, and Windows Security/System Event Logs.
2. **Cryptographic Anti-Tamper Assurance:** Implement an append-only evidence store in SQLite utilizing recursive SHA-256 hash chaining to guarantee non-repudiation.
3. **Explainable Rule-Based Correlation:** Design declarative, YAML-based correlation rules (R1 through R7) that reconstruct multi-stage activities with explainable confidence scoring, citing exact event IDs for every narrative assertion.
4. **Investigator Workbench:** Provide a web-based React dashboard featuring visual timeline rendering, an evidence provenance drawer, and one-click PDF forensic case reporting.
5. **Empirical Evaluation:** Measure agent resource overhead and conduct a human-subject experiment comparing ForensiTrace against raw Windows Event Viewer review.
