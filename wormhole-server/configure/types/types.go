package types

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// Configure define all settings here
type Configure struct {
	TLS struct {
		CAPath   string `yaml:"ca"`
		CertPath string `yaml:"cert"`
		KeyPath  string `yaml:"key"`
	} `yaml:"tls"`
	LocalAddress string `yaml:"local"`
}

// LoadConfigureFromPath load configure
func LoadConfigureFromPath(filepath string) (configure *Configure, err error) {
	var rawContent []byte
	if rawContent, err = ioutil.ReadFile(filepath); err == nil {
		configure = new(Configure)
		if err = yaml.Unmarshal(rawContent, configure); err != nil {
			configure = nil
		}
	}
	return
}
