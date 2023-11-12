from pyflowmeter.sniffer import create_sniffer

sniffer = create_sniffer(
            None,
            None,
            'file',
            'http://127.0.0.1:5000/send_traffic',
            'url',
        )

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    print('asd')
    sniffer.stop()
finally:
    sniffer.join()

print('end')