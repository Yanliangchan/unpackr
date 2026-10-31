import sys,random,time,pefile,lief,hashlib
lief.logging.disable() if hasattr(lief.logging,'disable') else None
files=sys.argv[2:]; n=int(sys.argv[1]); rng=random.Random(1)
stats={'pefile':[0,0,0],'lief':[0,0,0]}  # ok, none/err, exc
t={'pefile':0,'lief':0}
for f in files:
    orig=open(f,'rb').read()
    for i in range(n):
        b=bytearray(orig)
        for _ in range(rng.randint(1,16)): b[rng.randrange(min(4096,len(b)))]=rng.randrange(256)
        if rng.randrange(6)==0: b=b[:rng.randrange(len(b))]
        b=bytes(b)
        s=time.time()
        try:
            p=pefile.PE(data=b); p.parse_data_directories(); stats['pefile'][0]+=1
        except pefile.PEFormatError: stats['pefile'][1]+=1
        except Exception as e: stats['pefile'][2]+=1
        t['pefile']+=time.time()-s
        s=time.time()
        try:
            x=lief.PE.parse(list(b))
            if x is None: stats['lief'][1]+=1
            else:
                _=[i.name for i in x.imports]; _=[sec.name for sec in x.sections]; stats['lief'][0]+=1
        except Exception: stats['lief'][2]+=1
        t['lief']+=time.time()-s
print(stats,{k:round(v,1) for k,v in t.items()})
