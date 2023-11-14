# Python CICFlowMeter (PyFlowmeter)

> This project is cloned from [Python Wrapper CICflowmeter](https://gitlab.com/hieulw/cicflowmeter) and customized to fit my need. Therefore, it is not maintained actively. If there are any problems, please create an issue or a pull request.  


### Installation
```sh
pip install pyflowmeter
```

# Usage
```python
from pyflowmeter.sniffer import create_sniffer
```
## Parameters

* `input_file` [default=None]  
    * A .pcap file where capture offline data from  

* `input_interface` [default=None]  
    *  Interface or list of interfaces (default: None for sniffing on all interfaces).  

* server_endpoint [default=None]  
    * A server endpoint where the data of the flow will be sent. If it is set to `None`, no data will be sent.  

* verbose [default=False]  
    * Wheather or not to print a message when a new packet is read.

## Examples

### Sniff packets real-time from interface and send the flow to a server (**need root permission**): 
```python
from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            server_endpoint='http://127.0.0.1:5000/send_traffic',
            verbose=True
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
