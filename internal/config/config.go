package config

import (
    "fmt"
    "os"

    "gopkg.in/yaml.v3"
)

type Rule struct {
    ID          string   `yaml:"id"`
    Description string   `yaml:"description"`
    EventTypes  []string `yaml:"event_types"`

    CommRegex     string `yaml:"comm_regex,omitempty"`
    FilenameRegex string `yaml:"filename_regex,omitempty"`

    MinDestPort *int `yaml:"min_dest_port,omitempty"`
    MaxDestPort *int `yaml:"max_dest_port,omitempty"`
}

type Config struct {
    Rules []Rule `yaml:"rules"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read config: %w", err)
    }
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("unmarshal config: %w", err)
    }
    return &cfg, nil
}
