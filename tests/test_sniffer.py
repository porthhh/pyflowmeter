from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            input_file='tests\pcap_files\pkt.TCP.synflood.spoofed.pcap',
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