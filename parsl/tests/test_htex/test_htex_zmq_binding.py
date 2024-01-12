import pathlib
from unittest import mock

import psutil
import pytest
import zmq

from parsl import curvezmq
from parsl.executors.high_throughput.interchange import Interchange


def test_interchange_binding_no_address(tmpd_cwd: pathlib.Path):
    ix = Interchange(run_dir=tmpd_cwd)
    assert ix.interchange_address == "*"


def test_interchange_binding_with_address(tmpd_cwd: pathlib.Path):
    # Using loopback address
    address = "127.0.0.1"
    ix = Interchange(interchange_address=address, run_dir=tmpd_cwd)
    assert ix.interchange_address == address


def test_interchange_binding_with_non_ipv4_address(tmpd_cwd: pathlib.Path):
    # Confirm that a ipv4 address is required
    address = "localhost"
    with pytest.raises(zmq.error.ZMQError):
        Interchange(interchange_address=address, run_dir=tmpd_cwd)


def test_interchange_binding_bad_address(tmpd_cwd: pathlib.Path):
    """ Confirm that we raise a ZMQError when a bad address is supplied"""
    address = "550.0.0.0"
    with pytest.raises(zmq.error.ZMQError):
        Interchange(interchange_address=address, run_dir=tmpd_cwd)


def test_limited_interface_binding(tmpd_cwd: pathlib.Path):
    """ When address is specified the worker_port would be bound to it rather than to 0.0.0.0"""
    address = "127.0.0.1"
    ix = Interchange(interchange_address=address, run_dir=tmpd_cwd)
    ix.worker_result_port
    proc = psutil.Process()
    conns = proc.connections(kind="tcp")

    matched_conns = [conn for conn in conns if conn.laddr.port == ix.worker_result_port]
    assert len(matched_conns) == 1
    assert matched_conns[0].laddr.ip == address


@mock.patch.object(curvezmq.ServerContext, "socket", return_value=mock.MagicMock())
def test_interchange_curvezmq_sockets(mock_socket: mock.MagicMock, tmpd_cwd: pathlib.Path):
    address = "127.0.0.1"
    ix = Interchange(interchange_address=address, run_dir=tmpd_cwd)
    assert isinstance(ix.zmq_context, curvezmq.ServerContext)
    assert ix.zmq_context.encrypted
    assert mock_socket.call_count == 5
