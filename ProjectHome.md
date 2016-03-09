# Karma IDS #
Karma IDS is a project developed by Keith Biddlecomb as a part of his final thesis on Intrusion Detection Systems for the University of Virginia School of Engineering.

## What is Karma IDS ##
The system works by collecting data from several anomaly detection systems and state monitoring systems, including Snort, devialog, and OSSEC.  Each of the data collection tools has been modified to report inconsistencies that are then analyzed.  The system attempts to match user actions with system events to determine a cause-effect relationship between anomalies.

The idea behind the system is that matching anomalous action with the changes in system's state will produce enough information to make a better decision as to whether an anomaly is actually an intrusion attempt or not.  By generating a database of these action-event pairs, the system is able to reduce the number of false positives produced by comparing anomalies to similar anomalies in the past, and examining their effects on the system.

The name Karma-IDS comes from the principle that future events are determined by past actions.


---


**DO NOT USE THIS CODE**
This project is not intended to be released at this point, as the code is still under heavy development and several key features have not been implemented yet.  Please check back over the next few months for the first release.