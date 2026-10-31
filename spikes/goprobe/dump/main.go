package main
import ("fmt";"os";"time";"sort";"github.com/saferwall/pe")
func main(){
 for _,f:=range os.Args[1:]{
  t:=time.Now()
  p,err:=pe.New(f,&pe.Options{}); if err!=nil{fmt.Println(f,err);continue}
  if err:=p.Parse();err!=nil{fmt.Println(f,"parse",err)}
  el:=time.Since(t)
  var secs []string
  for _,s:=range p.Sections{ secs=append(secs,fmt.Sprintf("%s:%x:%x:%x",s.String(),s.Header.VirtualSize,s.Header.SizeOfRawData,s.Header.Characteristics)) }
  nimp:=0; var dlls []string
  for _,i:=range p.Imports{ nimp+=len(i.Functions); dlls=append(dlls,i.Name)}
  sort.Strings(dlls)
  ih,_:=p.ImpHash()
  fmt.Printf("%s\n time=%v machine=%x ep=%x ts=%x secs=%v\n imports=%d dlls=%v imphash=%s\n overlay=%d anomalies=%d authenticode=%v clr=%v\n",f,el,p.NtHeader.FileHeader.Machine,p.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64).AddressOfEntryPoint,p.NtHeader.FileHeader.TimeDateStamp,secs,nimp,dlls,ih,p.OverlayLength(),len(p.Anomalies),p.IsSigned,p.HasCLR)
 }
}
