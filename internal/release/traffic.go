package release

import (
	"encoding/json"
	"errors"
	"strings"
)

type nftSnapshot struct {
	NFTables []struct {
		Table *struct {
			Name    string `json:"name"`
			Comment string `json:"comment"`
		} `json:"table"`
		Counter *struct {
			Name  string `json:"name"`
			Bytes uint64 `json:"bytes"`
		} `json:"counter"`
	} `json:"nftables"`
}

func decodeTraffic(data []byte, table string) (string, map[string]uint64, error) {
	var snapshot nftSnapshot
	if len(data) > 4<<20 || json.Unmarshal(data, &snapshot) != nil {
		return "", nil, errors.New("invalid traffic snapshot")
	}
	source := ""
	counters := map[string]uint64{}
	for _, entry := range snapshot.NFTables {
		if entry.Table != nil && entry.Table.Name == table {
			source = entry.Table.Comment
		}
		if entry.Counter != nil {
			counters[entry.Counter.Name] = entry.Counter.Bytes
		}
	}
	if !strings.HasPrefix(source, "lineops-traffic-v1:") || len(source) > 100 {
		return "", nil, errors.New("traffic table ownership mismatch")
	}
	return source, counters, nil
}
