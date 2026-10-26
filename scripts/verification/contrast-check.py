import sys,json
def lum(h):
  h=h.lstrip('#'); r,g,b=[int(h[i:i+2],16)/255 for i in (0,2,4)]
  f=lambda c:c/12.92 if c<=0.03928 else ((c+0.055)/1.055)**2.4
  return 0.2126*f(r)+0.7152*f(g)+0.0722*f(b)
def cr(a,b):
  x,y=sorted([lum(a),lum(b)],reverse=True); return (x+0.05)/(y+0.05)
def table(fg,bg):
  rows=[]
  for fn,fc in fg.items():
    for bn,bc in bg.items():
      rows.append((fn,fc,bn,bc,round(cr(fc,bc),2)))
  return rows
sets=json.load(open((sys.argv[1] if len(sys.argv)>1 else __import__("os").path.join(__import__("os").path.dirname(__file__),"contrast-tokens.json"))))
for name,s in sets.items():
  print(f"## {name}")
  for fn,fc,bn,bc,c in table(s['fg'],s['bg']):
    need=s.get('need',{}).get(fn,4.5)
    print(f"{fn:22s} {fc} on {bn:8s} {bc}: {c:5.2f} {'OK' if c>=need else 'FAIL'} (need {need})")
