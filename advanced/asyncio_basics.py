# asyncio: thousands of waits at once, on one thread
#
# The last lesson used threads to wait on many things at once. Threads
# work for tens or hundreds of tasks, but each one costs memory, and
# switching between thousands of them is slow. asyncio takes a different
# approach: ONE thread runs an EVENT LOOP, and tasks politely hand control
# back whenever they're about to wait. Scanners, crawlers and servers
# that juggle thousands of connections (nmap-style tools, web servers,
# chat servers) work this way.
#
# Topics covered here:
#   1. Coroutines: async def, await, asyncio.run
#   2. Running many at once: gather and create_task
#   3. Timeouts: asyncio.wait_for
#   4. Limiting concurrency with a Semaphore (don't DoS anyone)
#   5. Errors in gather: return_exceptions
#   6. Real networking: a local server, and a client
#   7. Checking ports, on your OWN machine only
#   8. Blocking code inside async code: asyncio.to_thread
#   9. Practice, with tests
#
# HOW TO RUN IT
#   python3 asyncio_basics.py
#
# All networking here stays on 127.0.0.1 (your own machine), with ports
# the operating system picks. Scanning machines you don't own, or don't
# have written permission to test, is illegal in most countries.


import asyncio
import ipaddress
import time


# ---------------------------------------------------------------
# 1. Coroutines
# ---------------------------------------------------------------
#
#   async def lookup(ip): ...     defines a COROUTINE function
#   lookup("1.2.3.4")             makes a coroutine object; runs NOTHING yet
#   await lookup("1.2.3.4")       runs it, inside another coroutine
#   asyncio.run(main())           starts the event loop and runs main()
#
# `await` marks the places where a task may pause and let others run.
# The rule that catches everyone: inside async code, never call
# time.sleep() or anything else that blocks. It stops the WHOLE loop, so
# every other task freezes too. Use await asyncio.sleep() instead, and
# asyncio versions of network calls.

KNOWN_BAD = {"203.0.113.9", "198.51.100.23"}


async def check_reputation(ip, latency=0.1):
    await asyncio.sleep(latency)                       # waiting on "the network", politely
    return ip, ("malicious" if ip in KNOWN_BAD else "clean")


async def one_at_a_time(ips):
    return dict([await check_reputation(ip) for ip in ips])


# ---------------------------------------------------------------
# 2. Running many at once
# ---------------------------------------------------------------
#
# asyncio.gather(c1, c2, ...) runs coroutines CONCURRENTLY and returns
# their results in the order given. asyncio.create_task(c) starts one
# running in the background and returns a Task you can await later.

async def all_at_once(ips):
    return dict(await asyncio.gather(*(check_reputation(ip) for ip in ips)))


# ---------------------------------------------------------------
# 3. Timeouts
# ---------------------------------------------------------------
#
# A server that never answers must not hang the scan. wait_for() gives a
# coroutine a deadline; when it passes, the coroutine is CANCELLED and
# asyncio.TimeoutError is raised. (Python 3.11+ also has
# `async with asyncio.timeout(1):`, a context manager doing the same.)

async def with_deadline(ip, latency, deadline):
    try:
        return await asyncio.wait_for(check_reputation(ip, latency), timeout=deadline)
    except asyncio.TimeoutError:
        return ip, "timed out"


# ---------------------------------------------------------------
# 4. Limiting concurrency with a Semaphore
# ---------------------------------------------------------------
#
# gather() on 100,000 IPs would open 100,000 requests at once: you'd be
# rate limited, blocked, or you'd knock the service over. A SEMAPHORE is
# a counter of free slots: `async with sem:` waits for a slot, and gives
# it back at the end of the block (a context manager again). With
# Semaphore(10), at most 10 requests are ever in flight.

async def polite_scan(ips, limit=10):
    sem = asyncio.Semaphore(limit)
    in_flight = peak = 0

    async def one(ip):
        nonlocal in_flight, peak
        async with sem:
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                return await check_reputation(ip, 0.02)
            finally:
                in_flight -= 1

    results = dict(await asyncio.gather(*(one(ip) for ip in ips)))
    return results, peak


# ---------------------------------------------------------------
# 5. Errors in gather
# ---------------------------------------------------------------
#
# By default, the first exception in gather() is raised straight away and
# you lose every other result. return_exceptions=True puts each exception
# in the results list instead, so one bad host doesn't sink the scan.
# Check each result with isinstance(r, Exception).

async def sometimes_fails(ip):
    await asyncio.sleep(0.01)
    if ip.endswith(".13"):
        raise ConnectionResetError(f"{ip}: connection reset")
    return ip, "clean"


async def tolerant_scan(ips):
    results = await asyncio.gather(*(sometimes_fails(ip) for ip in ips), return_exceptions=True)
    ok = dict(r for r in results if not isinstance(r, Exception))
    errors = [str(r) for r in results if isinstance(r, Exception)]
    return ok, errors


# ---------------------------------------------------------------
# 6. Real networking: a server and a client
# ---------------------------------------------------------------
#
# asyncio.start_server(handler, host, port) listens for connections and
# calls handler(reader, writer) for each one, as its own task, so one
# slow client doesn't block the others. asyncio.open_connection(host,
# port) connects as a client. reader/writer are STREAMS: read with
# `await reader.readline()`, write with writer.write() then
# `await writer.drain()`.
#
# This server sends a BANNER, like real services do ("SSH-2.0-OpenSSH_9.6"
# or "220 mail.example.com ESMTP"). Banners tell attackers which software
# and version is running, which is why hardening guides say to trim them.
# Port 0 means "any free port": the OS picks one.

BANNER = b"SSH-2.0-LessonServer_1.0\r\n"


async def handle_client(reader, writer):
    # Clients can vanish at any moment: a port scanner connects and hangs
    # up at once. A server that doesn't expect that crashes the handler
    # (the first version of this lesson printed a ConnectionResetError
    # traceback for exactly that reason).
    try:
        writer.write(BANNER)
        await writer.drain()
        line = await reader.readline()                 # one line from the client
        writer.write(b"you said: " + line)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass                                           # they left; nothing to do
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass


async def start_lesson_server():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def talk_to(port, message):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    banner = await reader.readline()
    writer.write(message.encode() + b"\n")
    await writer.drain()
    reply = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return banner.decode().strip(), reply.decode().strip()


# ---------------------------------------------------------------
# 7. Checking ports, on your own machine only
# ---------------------------------------------------------------
#
# A port is "open" if something accepts a connection on it. A CONNECT
# check just tries open_connection: success means open; "connection
# refused" means closed; no answer before the timeout usually means a
# firewall dropped it ("filtered"). Many checks at once, each with a
# timeout, behind a semaphore: that's the core of a port scanner.
#
# This one REFUSES anything that isn't a loopback address (127.x.x.x or
# ::1). A guard like that, in the code, is the difference between a
# lesson and a tool that could be pointed at someone else's network.

class NotYourMachine(ValueError):
    pass


async def check_port(host, port, timeout=0.5):
    if not ipaddress.ip_address(host).is_loopback:
        raise NotYourMachine(f"{host} isn't this machine: only loopback addresses are allowed here")
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        # Caught FIRST: since Python 3.11 this is the built-in TimeoutError,
        # which is a kind of OSError, so the next line would swallow it.
        return port, "filtered"
    except OSError:                                    # e.g. ConnectionRefusedError
        return port, "closed"
    writer.close()
    await writer.wait_closed()
    return port, "open"


async def check_ports(host, ports, limit=50, timeout=0.5):
    sem = asyncio.Semaphore(limit)

    async def one(port):
        async with sem:
            return await check_port(host, port, timeout)

    return dict(await asyncio.gather(*(one(p) for p in ports)))


def free_port():
    """A port number that nothing is listening on (bind, read it, close)."""
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------
# 8. Blocking code inside async code
# ---------------------------------------------------------------
#
# Sometimes you must call something that BLOCKS: an old database driver
# or network library with no async version, socket.gethostbyname(). Call
# it directly inside async code and the whole loop freezes (the rule from
# section 1). asyncio.to_thread(f, *args) runs it in a worker thread and
# lets you await the result, so other tasks keep running meanwhile.
#
# to_thread is for code that WAITS. For heavy pure-Python COMPUTING, a
# thread still competes for the GIL (concurrency.py, section 7): hand that
# to a process pool with loop.run_in_executor(ProcessPoolExecutor(), f).
# (An earlier version of this demo used CPU-heavy hashing here, and
# whether the loop got a turn depended on thread scheduling: sometimes it
# showed the point, sometimes the opposite.)

def blocking_lookup(name):
    time.sleep(0.1)                                    # a blocking library call, standing in
    return f"{name} -> 192.0.2.80"


async def heartbeats_during(do_the_work):
    """Run do_the_work() while a heartbeat ticks every 5 ms; count the ticks."""
    ticks = 0

    async def heartbeat():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.005)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)                             # let the heartbeat start
    result = await do_the_work()
    beat.cancel()
    return result, ticks


async def blocking_directly():
    return blocking_lookup("intranet.example")         # WRONG in async code: freezes the loop


async def blocking_in_thread():
    return await asyncio.to_thread(blocking_lookup, "intranet.example")


# ---------------------------------------------------------------
# The lesson
# ---------------------------------------------------------------

async def lesson():
    ips = [f"203.0.113.{i}" for i in range(1, 51)]
    print("--- 1-2. 50 reputation checks, 0.1 s each ---")
    start = time.perf_counter()
    await one_at_a_time(ips[:10])
    print(f"  10 one at a time:  {time.perf_counter() - start:.2f}s")
    start = time.perf_counter()
    results = await all_at_once(ips)
    print(f"  50 all at once:    {time.perf_counter() - start:.2f}s  (one thread!)")
    print(f"  malicious: {[ip for ip, v in results.items() if v == 'malicious']}")

    print("\n--- 3-5. Deadlines, limits, and errors ---")
    print(f"  {await with_deadline('192.0.2.1', latency=2, deadline=0.1)}")
    _, peak = await polite_scan(ips, limit=10)
    print(f"  polite scan of 50: never more than {peak} requests at once")
    ok, errors = await tolerant_scan([f"192.0.2.{i}" for i in range(10, 16)])
    print(f"  tolerant scan: {len(ok)} answered, errors: {errors}")

    print("\n--- 6-7. A real local server, a client, and a port check ---")
    server, port = await start_lesson_server()
    async with server:
        banner, reply = await talk_to(port, "hello")
        print(f"  banner: {banner!r}   reply: {reply!r}")
        closed = free_port()
        print(f"  ports on 127.0.0.1: {await check_ports('127.0.0.1', [port, closed])}")
    try:
        await check_port("192.0.2.10", 22)
    except NotYourMachine as e:
        print(f"  refused: {e}")

    print("\n--- 8. A blocking call: directly, then with to_thread (0.1 s, heartbeat every 5 ms) ---")
    _, frozen = await heartbeats_during(blocking_directly)
    _, running = await heartbeats_during(blocking_in_thread)
    print(f"  called directly:   {frozen} heartbeats  (the whole loop froze)")
    print(f"  with to_thread:    {running} heartbeats (the loop kept running)")


# ---------------------------------------------------------------
# 9. Practice and tests
# ---------------------------------------------------------------
#
# Practice: write grab_banners(host, ports, limit, timeout): for each OPEN
# port, connect and read the first line the service sends (its banner),
# with a timeout for services that wait for the client to speak first.
# Return {port: banner or None}. Keep the loopback-only guard. Solution
# below.

async def grab_banner(host, port, timeout=0.5):
    if not ipaddress.ip_address(host).is_loopback:
        raise NotYourMachine(host)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return port, None
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
        return port, line.decode(errors="replace").strip() or None
    except asyncio.TimeoutError:
        return port, None                               # it waits for us to speak first
    finally:
        writer.close()
        await writer.wait_closed()


async def grab_banners(host, ports, limit=20, timeout=0.5):
    sem = asyncio.Semaphore(limit)

    async def one(p):
        async with sem:
            return await grab_banner(host, p, timeout)
    return dict(await asyncio.gather(*(one(p) for p in ports)))


async def async_tests():
    ips = [f"203.0.113.{i}" for i in range(1, 31)]

    # 1-2. Concurrent waits overlap; same answers either way
    start = time.perf_counter()
    together = await all_at_once(ips)
    assert time.perf_counter() - start < 0.5          # 30 x 0.1s of waiting, overlapped
    assert await one_at_a_time(ips[:3]) == {ip: together[ip] for ip in ips[:3]}
    assert together["203.0.113.9"] == "malicious"

    # 3. Timeouts cancel slow work
    assert await with_deadline("192.0.2.1", latency=1, deadline=0.05) == ("192.0.2.1", "timed out")
    assert await with_deadline("192.0.2.1", latency=0.01, deadline=1) == ("192.0.2.1", "clean")

    # 4. The semaphore really caps in-flight requests
    results, peak = await polite_scan(ips, limit=5)
    assert len(results) == 30 and peak == 5

    # 5. One error doesn't sink the scan
    ok, errors = await tolerant_scan([f"192.0.2.{i}" for i in range(10, 16)])
    assert len(ok) == 5 and errors == ["192.0.2.13: connection reset"]

    # 6-7. A real server on loopback: talk to it, and check ports
    server, port = await start_lesson_server()
    async with server:
        banner, reply = await talk_to(port, "ping")
        assert banner == "SSH-2.0-LessonServer_1.0" and reply == "you said: ping"
        closed = free_port()
        assert await check_ports("127.0.0.1", [port, closed]) == {port: "open", closed: "closed"}
        # Practice: banners from open ports only
        assert await grab_banners("127.0.0.1", [port, closed]) == {port: "SSH-2.0-LessonServer_1.0", closed: None}

    # The loopback-only guard
    for not_mine in ("192.0.2.10", "10.0.0.1", "8.8.8.8"):
        try:
            await check_port(not_mine, 22)
        except NotYourMachine:
            pass
        else:
            raise AssertionError(f"scanned {not_mine}")
    assert (await check_port("::1", free_port()))[1] in ("closed", "filtered")   # IPv6 loopback is fine

    # 8. A blocking call freezes the loop; to_thread doesn't
    result, frozen = await heartbeats_during(blocking_directly)
    assert result.endswith("192.0.2.80") and frozen <= 1
    result, running = await heartbeats_during(blocking_in_thread)
    assert result.endswith("192.0.2.80") and running >= 5


def run_tests():
    asyncio.run(async_tests())
    print("All tests passed!")


if __name__ == "__main__":
    asyncio.run(lesson())
    print()
    run_tests()
