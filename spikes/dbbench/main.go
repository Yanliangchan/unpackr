package main
import ("database/sql";"fmt";"os";"time"
 _ "modernc.org/sqlite"
 _ "github.com/ncruces/go-sqlite3/driver"
 _ "github.com/ncruces/go-sqlite3/embed")
func bench(name,drv,dsn string){
 os.Remove("b.db"); os.Remove("b.db-wal"); os.Remove("b.db-shm")
 db,err:=sql.Open(drv,dsn); if err!=nil{panic(err)}; db.SetMaxOpenConns(1)
 db.Exec("PRAGMA journal_mode=WAL"); db.Exec("PRAGMA synchronous=NORMAL")
 db.Exec("CREATE TABLE ioc(id INTEGER PRIMARY KEY, sha TEXT, kind TEXT, val TEXT)"); db.Exec("CREATE INDEX i1 ON ioc(val)")
 _,e:=db.Exec("CREATE VIRTUAL TABLE n USING fts5(body)"); fts:= e==nil
 t:=time.Now(); tx,_:=db.Begin(); st,_:=tx.Prepare("INSERT INTO ioc(sha,kind,val) VALUES(?,?,?)")
 for i:=0;i<300000;i++{ st.Exec(fmt.Sprintf("%064d",i%5000),"url",fmt.Sprintf("http://h%d.example/p",i)) }
 tx.Commit(); ins:=time.Since(t)
 t=time.Now(); for i:=0;i<20000;i++{ var c int; db.QueryRow("SELECT count(*) FROM ioc WHERE val=?",fmt.Sprintf("http://h%d.example/p",i*7)).Scan(&c) }
 q:=time.Since(t)
 fmt.Printf("%-10s insert300k=%v 20kLookups=%v fts5=%v\n",name,ins.Round(time.Millisecond),q.Round(time.Millisecond),fts)
}
func main(){ bench("modernc","sqlite","file:b.db"); bench("ncruces","sqlite3","file:b.db") }
