package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/golang/glog"
)

func SetSysctl(path string, value int) error {

	sysctlPath := fmt.Sprintf("/proc/sys/%s", path)
	if _, err := os.Stat(sysctlPath); err != nil {
		if os.IsNotExist(err) {
			glog.Infof("%s not found, could not set value: %s, Does your kernel support this feature?", sysctlPath)
			return nil
		}
		glog.Errorf("error stating: %s : %s", sysctlPath, err.Error())
		return nil
	}
	return ioutil.WriteFile(sysctlPath, []byte(strconv.Itoa(value)), 0640)
}
