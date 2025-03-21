# Intrusion_detection_system
Real-Time Intrusion Detection System (IDS) using Random Forest
 **Project Overview**
This project implements a **Real-Time Intrusion Detection System (IDS)** using a **Random Forest Classifier** to detect malicious network traffic. The system is capable of:

- Training a machine learning model using the **KDD Cup 99** dataset.
- Detecting real-time intrusions by capturing live network traffic.
- Processing captured packets dynamically and classifying them as **Normal Traffic** or **Attack Traffic**.

---

---

1. Model Training (`model.py`)**

 **Training Script Description**
The script loads the **KDD Cup 99** dataset, processes it, and trains a **Random Forest Classifier**. Key tasks include:

- Loading and preprocessing the dataset.
- Handling categorical data using one-hot encoding.
- Scaling features with `StandardScaler`.
- Splitting data into training and testing sets.
- Training the Random Forest model with `100` estimators.
- Saving the trained model and scaler as `.pkl` files using `joblib`.
  **Usage**
Run the following command to train and save the model:

```bash
python train_model.py
```
Output Files
ids_model.pkl – Trained Random Forest model.

scaler.pkl – Standard Scaler for real-time traffic processing.


2.Real-Time Detection Script 

Description

This script captures live network traffic using scapy and processes the packets in real time. Key tasks include:

Sniffing network traffic on the IP layer.
Extracting relevant features such as protocol, packet size, and flags.
One-hot encoding and aligning features to match the training set.
Scaling features using the pre-trained scaler.pkl.
Making predictions using the trained ids_model.pkl.
Printing results for each packet:
 No intrusion detected (Normal Traffic)
 Intrusion detected! (Attack Traffic)

Usage
Run the following command to start real-time detection:

```bash

sudo python real_time_detection.py
```
