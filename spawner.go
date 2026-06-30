package gonnect

import "sync"

func spawn(spawner Spawner, worker func(), name string) error {
	if spawner == nil {
		go worker()
		return nil
	}
	_, err := spawner.Spawn(worker, name)
	return err
}

func spawnWg(
	spawner Spawner,
	worker func(),
	wg *sync.WaitGroup,
	name string,
) error {
	if spawner == nil {
		wg.Go(worker)
		return nil
	}
	_, err := spawner.SpawnWg(worker, wg, name)
	return err
}
