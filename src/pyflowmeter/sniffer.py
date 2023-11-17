from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class


def create_sniffer(
    input_file=None, input_interface=None, server_endpoint=None, verbose=False, to_csv=False,
    output_file=None
):
    assert (to_csv == False) or (output_file is not None)

    NewFlowSession = generate_session_class(server_endpoint, verbose, to_csv, output_file)

    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )