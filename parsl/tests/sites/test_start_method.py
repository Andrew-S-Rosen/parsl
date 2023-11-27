import os
import psutil
from contextlib import contextmanager

from pytest import mark, raises

import parsl
from parsl.providers import LocalProvider
from parsl.channels import LocalChannel
from parsl.config import Config
from parsl.executors import HighThroughputExecutor
from parsl import python_app


@python_app()
def get_pid():
    return os.getpid()


@contextmanager
def config(start_method: str, **kwargs):
    my_config = Config(
        executors=[
            HighThroughputExecutor(
                label="fork",
                worker_debug=True,
                max_workers=2,
                provider=LocalProvider(
                    channel=LocalChannel(),
                    init_blocks=1,
                    max_blocks=1,
                ),
                start_method=start_method
            )
        ],
        strategy='none',
    )
    dfk = parsl.load(my_config)
    try:
        yield dfk
    finally:
        dfk.cleanup()
        parsl.clear()


@mark.local
@mark.parametrize("start_method", ["fork", "thread"])
def test_start_method(start_method: str):
    with config(start_method) as dfk:
        worker_pid = get_pid().result()

        htex: HighThroughputExecutor = dfk.config.executors[0]
        submit_pid = int(next(iter(htex.provider.resources.values()))["remote_pid"])
        submit_proc = psutil.Process(submit_pid)
        manager_pid = submit_proc.children(recursive=True)[2].pid

        if start_method == "thread":
            assert worker_pid == manager_pid
        else:
            assert worker_pid != manager_pid


@mark.local
def test_htex_config_failures():
    with raises(ValueError) as exc:
        HighThroughputExecutor(start_method='thread', available_accelerators=1)
    assert 'Accelerator' in str(exc)

    with raises(ValueError) as exc:
        HighThroughputExecutor(start_method='thread', cpu_affinity='block')
    assert 'Thread affinity' in str(exc)

    with raises(ValueError) as exc:
        HighThroughputExecutor(start_method='not real', cpu_affinity='block')
    assert 'Start method "not real" not recognized' in str(exc)
