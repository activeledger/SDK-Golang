package sdk

import(
  "os"
	"fmt"  
)

func checkError(err error){
	if err !=nil{
		fmt.Println("Fatal Error ", err.Error())
		os.Exit(1)
	}

}