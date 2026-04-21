# Maac4ML

Code for **Maac4ML: Multi-authority Attribute-Based Access Control for Privacy-Preserving Machine Learning Deployment**.

This repository contains the implementation used for the paper’s experimental section, including:

- **basic cryptographic calibration**
  - composite-order bilinear-group setup
  - element-size measurement
  - exponentiation and pairing timing

- **MABIPFE prototype**
  - `GSetup`
  - `AASetup`
  - `KGen`
  - `Enc`
  - `Dec`

- **Maac4ML prototype demo**
  - system-level latency
  - storage and communication overhead
  - authority-scaling experiments
  - correctness of authorized decryption and rejection of unauthorized access

---

## Highlights

- Prototype implementation of **multi-authority attribute-based inner-product functional encryption**
- System-level measurements for **online latency**, **ciphertext size**, **request/response size**, and **authority scaling**
- Built-in demo for **bounded discrete-log recovery by exhaustive search**
- Experimental setting consistent with the paper: vector coordinates are deliberately restricted to **8-bit values**

---

## Repository Scope

This code supports the paper’s experiments in two layers:

### 1. Cryptographic calibration
Used to measure:

- public-parameter generation
- exponentiation in `G`
- exponentiation in `GT`
- pairing cost
- element sizes in `G`, `GT`, and `Z_N`

### 2. Prototype evaluation
Used to measure:

- `AASetup`, `KGen`, `Enc`, `Dec`
- end-to-end online latency
- ciphertext and published-model size
- request/response communication overhead
- scalability under different numbers of authorities

---

## Bounded Recovery Demo

The prototype includes a demo for the final bounded-range recovery step.

To make exhaustive recovery feasible, each coordinate of the protected vectors is intentionally restricted to the **8-bit range**

\[
[-128, 127]
\]

If the vector dimension is \(s\), then the inner product lies in the bounded interval

\[
[-s \cdot 127 \cdot 127,\; s \cdot 127 \cdot 127]
\]

and the final value can be recovered by **exhaustive enumeration**.

This part is included as a prototype demonstration of bounded-range recovery, consistent with the paper’s experimental setting.

---

## Environment

Recommended setup:

- **Java 8+**
- **JPBC**
- Ubuntu / Linux environment recommended for reproduction

Make sure that:

- JPBC dependencies are correctly imported
- package names match your project structure
- the correct `main` class is selected when running experiments

---

## Running the Code

### Basic calibration
Run the public-parameter / pairing benchmark classes to obtain:

- setup time
- exponentiation time
- pairing time
- element sizes

### Prototype demo
Run the Maac4ML demo to obtain outputs such as:

- plaintext and recovered inner product
- authorized / unauthorized decryption result
- prototype-level metrics
- authority-scaling results

Typical reported metrics include:

- `PP generation`
- `AASetup total / avg`
- `KGen total / avg / max`
- `Enc`
- `Dec`
- `Online end-to-end`
- ciphertext bytes
- request / response bytes

Some versions also print a decryption breakdown such as:

- `Dec core`
- `DLog recovery`
- `Dec total`

---

## Notes

- `Enc` mainly reflects a **one-time offline publishing cost**
- `KGen` and `Dec` are more relevant to **repeated online use**
- In practical deployment, different authorities can generate key components **in parallel**, so **per-authority average cost** is often more informative than aggregate work
- Timing results may vary across machines and JVM states; averaging over multiple runs is recommended

---

## Reference

If you use this code, please cite the corresponding Maac4ML paper.

---
