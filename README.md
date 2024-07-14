# Python CICFlowMeter (PyFlowmeter)
[![Downloads](https://static.pepy.tech/badge/pyflowmeter)](https://pepy.tech/project/pyflowmeter)
> This project is cloned from [Python Wrapper CICflowmeter](https://gitlab.com/hieulw/cicflowmeter) and customized to fit my need. Therefore, it is not maintained actively. If there are any problems, please create an issue or a pull request.  


### Installation
```sh
pip install --upgrade pip
pip install pyflowmeter
```

# Usage
```python
from pyflowmeter.sniffer import create_sniffer
```
This function returns a `scapy.sendrecv.AsyncSniffer` object.

## Parameters

* `input_file` [default=None]  
    * A .pcap file where capture offline data from. If it is set to ´None´, the data will be capture from `input_interface`

* `input_interface` [default=None]  
    *  Interface or list of interfaces (default: None for sniffing on all interfaces).  

* `server_endpoint` [default=None]  
    * A server endpoint where the data of the flow will be sent. If it is set to `None`, no data will be sent.  

* `verbose` [default=False]  
    * Wheather or not to print a message when a new packet is read.

* `to_csv` [defalut=Fasle]  
    * Wheather or not to save the output flows as csv. The data will be saved on `output_file`.

* `output_file` [default=None]  
    * File to store the data. If `to_csv` is set to `False`, this parameter will be ignored.  

* `sending_interval` [defalut=1]  
    * The frequency, in seconds, at which data will be sent to the server. If `server_endpoint` is None, this parameter will be ignored.

## Examples

### Sniff packets real-time from interface and send the flow to a server every 5 seconds(**need root permission**): 
```python
from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            server_endpoint='http://127.0.0.1:5000/send_traffic',
            verbose=True,
            sending_interval=5
        )

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    print('Stopping the sniffer')
    sniffer.stop()
finally:
    sniffer.join()
```

### Get CSV analysis from a pcap file:
```python
from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            input_file='path_to_the_file.pcap',
            to_csv=True,
            output_file='./flows_test.csv',
        )

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    print('Stopping the sniffer')
    sniffer.stop()
finally:
    sniffer.join()
```

### Simulate offline traffic from a file and send the data to a server:
```python
from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            input_file='path_to_the_file.pcap',
            server_endpoint='http://127.0.0.1:5000/send_traffic',
        )

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    print('Stopping the sniffer')
    sniffer.stop()
finally:
    sniffer.join()
```

- Reference: https://www.unb.ca/cic/research/applications.html#CICFlowMeter
