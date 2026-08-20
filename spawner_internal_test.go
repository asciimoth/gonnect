package gonnect

import (
	"sync"
	"testing"
)

type testSpawner struct {
	spawnNames   []string
	spawnWgNames []string
}

func (s *testSpawner) Spawn(worker func(), name string) (uint64, error) {
	s.spawnNames = append(s.spawnNames, name)
	worker()
	return uint64(len(s.spawnNames)), nil
}

func (s *testSpawner) SpawnWg(
	worker func(),
	wg *sync.WaitGroup,
	name string,
) (uint64, error) {
	s.spawnWgNames = append(s.spawnWgNames, name)
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker()
	}()
	return uint64(len(s.spawnWgNames)), nil
}

func TestSpawnUsesCustomSpawner(t *testing.T) {
	spawner := &testSpawner{}
	ran := false

	if err := spawn(spawner, func() { ran = true }, "worker"); err != nil {
		t.Fatalf("spawn() error = %v", err)
	}
	if !ran {
		t.Fatal("spawn() did not run worker")
	}
	if len(spawner.spawnNames) != 1 || spawner.spawnNames[0] != "worker" {
		t.Fatalf("spawn names = %v, want worker", spawner.spawnNames)
	}
}

func TestSpawnWgUsesCustomSpawner(t *testing.T) {
	spawner := &testSpawner{}
	var wg sync.WaitGroup
	ran := false

	if err := spawnWg(
		spawner,
		func() { ran = true },
		&wg,
		"worker-wg",
	); err != nil {
		t.Fatalf("spawnWg() error = %v", err)
	}
	wg.Wait()
	if !ran {
		t.Fatal("spawnWg() did not run worker")
	}
	if len(spawner.spawnWgNames) != 1 ||
		spawner.spawnWgNames[0] != "worker-wg" {
		t.Fatalf("spawnWg names = %v, want worker-wg", spawner.spawnWgNames)
	}
}
