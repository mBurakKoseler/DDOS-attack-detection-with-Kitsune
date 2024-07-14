# DDOS-attack-detection-w-Kitsune
Working on developing and detailing DDOS ​​attack detection with kitsune
The Kitsune project is a system that uses artificial intelligence and machine learning techniques to detect anomalies in network traffic.

Resource:
Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, and Asaf Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", Network and Distributed System Security Symposium 2018 (NDSS'18)

--Information about the general purpose of the project and the data set
  Mirai is used as ready network traffic data in the project. The Mirai DDOS dataset is a dataset containing attacks of the Mirai botnet. This data set typically includes network traffic logs or packet capture (pcap) files. This package file, consisting of approximately 700.000 packages, contains DDOS attack packages after approximately 120 thousandth packages. The first part of this package, which does not include the attack package, is useful for training and pre-anomaly detection training.
Kitsune extracts attributes from network traffic and feeds these attributes into a machine learning model. Feature vectors are processed by an anomaly detection algorithm. Kitsune often uses machine learning algorithms such as deep learning techniques and autoencoders. In the application phase, the model analyzes the new data stream and tries to detect abnormal behavior.


--Changes and improvements made on the project
a) Parameter research&change
    Old parameters:
    [ max_autoencoder_size=10, FM_grace_period=5000, AD_grace_period=50000, learning_rate=0.1, hidden_ratio=0.75, threshold=0.5 ]
    New parameters:
    [ max_autoencoder_size: 15, FM_grace_period: 10000, AD_grace_period: 75000, learning_rate: 0.05, hidden_ratio: 0.8, threshold: 0.4 ]
--
b) Logging and Error Tracking
  During and after attack detection, indexes were assigned to packages to more clearly understand when and in which package the attack started or ended. The current time and the moment in which the code is running are shown separately. And these data are saved in the file named attack_detection.txt.
--
c) Distribution of Attack Times
  It helps understand the intensity of attacks and their tendency to increase or decrease over certain time periods. Matplotlib is used to visualize the results of the code.
--  
d) Post-Attack Calculations
Calculations have been added to the code to obtain more information from the data in the pcap file. These calculations allow us to learn the total attack traffic size, the elapsed time and the average byte size per second.
--
e) Statistical Calculations
Mean Anomaly Score and Standard Deviation. These statistics are used to evaluate the system's ability to detect behavior that deviates from normal. The higher the average score means the system detects more anomalies overall. Standard deviation shows how unstable or variable the system is.
--
f) Reporting
All graphs and calculation results resulting from this addition are shown in the report and the report is saved as a pdf.
--
All these processes were translated into Turkish and printed out.

