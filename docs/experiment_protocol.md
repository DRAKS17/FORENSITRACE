# ForensiTrace - Evaluation Experiment Protocol (DAKSH)

**Lead Investigator:** DAKSH  
**Reviewer:** AKASH  
**Target Hypothesis:** Reconstructed, cross-source forensic correlation significantly reduces investigator comprehension time and error rates compared to raw Windows Event Viewer analysis.

---

## 1. Study Design & Methodology
- **Participants:** 8–10 computer science undergraduate classmates who have not participated in the development of ForensiTrace. Prior experience with Windows Event Viewer is recorded (Novice / Intermediate / Advanced).
- **Design:** Within-subject, counterbalanced 2x2 factorial design.
  - Half the participants begin with Windows Event Viewer (Control) and proceed to ForensiTrace (Treatment).
  - Half the participants begin with ForensiTrace and proceed to Windows Event Viewer.
  - Scenario A (Kingston USB, `backdoor_payload.exe`) and Scenario A' (SanDisk USB, `update_helper.exe`) are alternated to eliminate order and difficulty bias.
- **Pilot Phase:** Conducted with 2 pilot participants to refine question clarity. Pilot data is excluded from final quantitative analysis.

---

## 2. Experimental Task & Questions
Participants are provided with either the raw Event Viewer log export (or live VM) or the ForensiTrace React Dashboard, and must answer five standardized forensic investigation questions:

1. **Hardware Identification:** Which external storage device was connected to the host?
2. **Artifact Staging:** Which file was copied or staged on the storage media?
3. **Execution Confirmation:** Was the staged file subsequently executed as a process?
4. **Attack Sequence:** In what exact chronological order did the actions occur?
5. **Temporal Timeline:** What were the exact timestamps for the device arrival, file creation, and execution?

### Ground Truth Answer Key
- **Scenario A:**
  1. Kingston DataTraveler (`E:`)
  2. `E:\backdoor_payload.exe` (512 KB)
  3. Yes, spawned via process ID 5120 (Event 4688)
  4. USB Connection &rarr; File Creation &rarr; Process Execution
  5. As recorded in `scenarios/ground_truth_a.json`
- **Scenario A':**
  1. SanDisk Ultra Flair (`F:`)
  2. `F:\update_helper.exe` (1 MB)
  3. Yes, spawned via process ID 6244 (Event 4688)
  4. USB Connection &rarr; File Creation &rarr; Process Execution
  5. As recorded in `scenarios/ground_truth_a_prime.json`

---

## 3. Evaluation Metrics & Measurement
1. **Time to Completion ($T$):** Total seconds elapsed from task prompt presentation to final question submission.
2. **Accuracy Score ($S$):** Number of questions correctly answered (0 to 5 points).
3. **Subjective Cognitive Load:** 5-point Likert scale rating perceived difficulty (1 = Trivial, 5 = Overwhelming).

---

## 4. Experimental Results Summary

| Participant | Tool Order | Scenario Order | Event Viewer Time (s) | Event Viewer Score (/5) | ForensiTrace Time (s) | ForensiTrace Score (/5) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| P01 | EV &rarr; FT | A &rarr; A' | 385 | 3/5 | 74 | 5/5 |
| P02 | FT &rarr; EV | A' &rarr; A | 410 | 2/5 | 62 | 5/5 |
| P03 | EV &rarr; FT | A' &rarr; A | 290 | 4/5 | 55 | 5/5 |
| P04 | FT &rarr; EV | A &rarr; A' | 360 | 3/5 | 68 | 5/5 |
| P05 | EV &rarr; FT | A &rarr; A' | 440 | 2/5 | 81 | 5/5 |
| P06 | FT &rarr; EV | A' &rarr; A | 315 | 4/5 | 59 | 5/5 |
| P07 | EV &rarr; FT | A' &rarr; A | 390 | 3/5 | 70 | 5/5 |
| P08 | FT &rarr; EV | A &rarr; A' | 350 | 3/5 | 65 | 5/5 |
| **Median** | — | — | **367.5 s** | **3.0 / 5** | **66.5 s** | **5.0 / 5** |

### Key Findings & Discussion
- **81.9% Reduction in Investigation Time:** Participants using the ForensiTrace correlation dashboard answered all five questions in a median of 66.5 seconds, compared to 367.5 seconds using raw Event Viewer.
- **Error Elimination:** 100% of participants achieved a perfect 5/5 score using ForensiTrace, whereas participants reviewing raw Event Logs frequently missed the exact file copy action or inverted the sequence order.
