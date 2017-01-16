package client

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// Configure define all settings here
type Configure struct {
	TLS struct {
		CAPath     string `yaml:"ca"`
		CertPath   string `yaml:"cert"`
		KeyPath    string `yaml:"key"`
		ServerName string `yaml:"server"`
	} `yaml:"tls"`
	RemoteAddress   string            `yaml:"remote"`
	ForwardServices map[string]string `yaml:"services"`
}

// LoadConfigureFromPath load initialization
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
