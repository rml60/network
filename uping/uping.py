""" µPing (MicroPing) for MicroPython
    based on
      copyright (c) 2018 Shawwwn <shawwwn1@gmail.com>
      License: MIT
      https://gist.github.com/shawwwn/91cc8979e33e82af6d99ec34c38195fb
    modified:
      Author: Rainer Maier-Lohmann
"""

""" Internet Checksum Algorithm
    Author: Olav Morken
    https://github.com/olavmrk/python-ping/blob/master/ping.py
    @data: bytes
"""
from urandom import randint
from uctypes import addressof, struct, BIG_ENDIAN, INT16, UINT8, UINT16, UINT64
from uselect import select
from usocket import socket, getaddrinfo, AF_INET, SOCK_RAW
from ustruct  import unpack
from utime import ticks_us, sleep_us

def checksum(data):
    if len(data) & 0x1: # Odd number of bytes
        data += b'\0'
    cs = 0
    for pos in range(0, len(data), 2):
        b1 = data[pos]
        b2 = data[pos + 1]
        cs += (b1 << 8) + b2
    while cs >= 0x10000:
        cs = (cs & 0xffff) + (cs >> 16)
    cs = ~cs & 0xffff
    return cs

def ping(host, count=3, timeout=500, interval=250, quiet=False, size=32):
  # prepare packet
  assert size >= 16, "paket size too small"
  pkt = b'Q'*size
  pkt_desc = { "type": UINT8 | 0
               , "code": UINT8 | 1
               , "checksum": UINT16 | 2
               , "id": UINT16 | 4
               , "seq": INT16 | 6
               , "timestamp": UINT64 | 8
               } # packet header descriptor
  h = struct(addressof(pkt), pkt_desc, BIG_ENDIAN)
  h.type = 8 # ICMP_ECHO_REQUEST
  h.code = 0
  h.checksum = 0
  h.id = randint(0, 65535)
  h.seq = 1

  # init socket
  sock = socket(AF_INET, SOCK_RAW, 1)
  sock.setblocking(0)
  sock.settimeout(timeout/1000)
  try:
    addr = getaddrinfo(host, 1)[0][-1][0] # ip address
  except:
    print("Unable to resolve: "+host)
    sock.close()
    return(0,0)
  addr = getaddrinfo(host, 1)[0][-1][0] # ip address
  sock.connect((addr, 1))
  #print(dir(sock))
  if not quiet:
    print("PING %s (%s): %u data bytes" % (host, addr, len(pkt)))

  seqs = list(range(1, count+1)) # [1,2,...,count]
  c = 1
  t = 0
  n_trans = 0
  n_recv = 0
  finish = False
  while t < timeout:
    if t==interval and c<=count:
      # send packet
      h.checksum = 0
      h.seq = c
      h.timestamp = ticks_us()
      h.checksum = checksum(pkt)
      try:
        resp = sock.send(pkt)
      except Exception as e:
        if not quiet:
          print('ERROR:', e)
        resp = None
      if  resp == size:
        n_trans += 1
        t = 0 # reset timeout
      else:
        seqs.remove(c)
      c += 1
    # recv packet
    while 1:
      socks, _, _ = select([sock], [], [], 0)
      if socks:
        resp = socks[0].recv(4096)
        resp_mv = memoryview(resp)
        h2 = struct(addressof(resp_mv[20:]), pkt_desc, BIG_ENDIAN)
        # TODO: validate checksum (optional)
        seq = h2.seq
        if h2.type==0 and h2.id==h.id and (seq in seqs): # 0: ICMP_ECHO_REPLY
          t_elasped = (ticks_us()-h2.timestamp) / 1000
          ttl = unpack('!B', resp_mv[8:9])[0] # time-to-live
          n_recv += 1
          if not quiet:
            print("%u bytes from %s: icmp_seq=%u, ttl=%u, time=%f ms" % (len(resp), addr, seq, ttl, t_elasped))
          seqs.remove(seq)
        if len(seqs) == 0:
          finish = True
          break
      else:    
        break

    if finish:
      break

    sleep_us(100)
    t += 1

  # close
  sock.close()
  #ret = (n_trans, n_recv)
  if not quiet:
    print("%u packets transmitted, %u packets received" % (n_trans, n_recv))

  return (n_trans, n_recv)