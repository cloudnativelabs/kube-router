package tsdb_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/influxdata/influxdb/influxql"
	"github.com/influxdata/influxdb/models"
	"github.com/influxdata/influxdb/pkg/deep"
	"github.com/influxdata/influxdb/tsdb"
	_ "github.com/influxdata/influxdb/tsdb/engine"
	_ "github.com/influxdata/influxdb/tsdb/index"
	"github.com/influxdata/influxdb/tsdb/index/inmem"
)

func TestShardWriteAndIndex(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)

	// Calling WritePoints when the engine is not open will return
	// ErrEngineClosed.
	if got, exp := sh.WritePoints(nil), tsdb.ErrEngineClosed; got != exp {
		t.Fatalf("got %v, expected %v", got, exp)
	}

	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}

	pt := models.MustNewPoint(
		"cpu",
		models.Tags{{Key: []byte("host"), Value: []byte("server")}},
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err := sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}

	pt.SetTime(time.Unix(2, 3))
	err = sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}

	validateIndex := func() {
		cnt := sh.SeriesN()
		if got, exp := cnt, int64(1); got != exp {
			t.Fatalf("got %v series, exp %v series in index", got, exp)
		}
	}

	validateIndex()

	// ensure the index gets loaded after closing and opening the shard
	sh.Close()

	sh = tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}

	validateIndex()

	// and ensure that we can still write data
	pt.SetTime(time.Unix(2, 6))
	err = sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestMaxSeriesLimit(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "db", "rp", "1")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.Config.MaxSeriesPerDatabase = 1000
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)

	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}

	// Writing 1K series should succeed.
	points := []models.Point{}

	for i := 0; i < 1000; i++ {
		pt := models.MustNewPoint(
			"cpu",
			models.Tags{{Key: []byte("host"), Value: []byte(fmt.Sprintf("server%d", i))}},
			map[string]interface{}{"value": 1.0},
			time.Unix(1, 2),
		)
		points = append(points, pt)
	}

	err := sh.WritePoints(points)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Writing one more series should exceed the series limit.
	pt := models.MustNewPoint(
		"cpu",
		models.Tags{{Key: []byte("host"), Value: []byte("server9999")}},
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err = sh.WritePoints([]models.Point{pt})
	if err == nil {
		t.Fatal("expected error")
	} else if exp, got := `partial write: max-series-per-database limit exceeded: (1000) dropped=1`, err.Error(); exp != got {
		t.Fatalf("unexpected error message:\n\texp = %s\n\tgot = %s", exp, got)
	}

	sh.Close()
}

func TestShard_MaxTagValuesLimit(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "db", "rp", "1")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.Config.MaxValuesPerTag = 1000
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)

	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}

	// Writing 1K series should succeed.
	points := []models.Point{}

	for i := 0; i < 1000; i++ {
		pt := models.MustNewPoint(
			"cpu",
			models.Tags{{Key: []byte("host"), Value: []byte(fmt.Sprintf("server%d", i))}},
			map[string]interface{}{"value": 1.0},
			time.Unix(1, 2),
		)
		points = append(points, pt)
	}

	err := sh.WritePoints(points)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// Writing one more series should exceed the series limit.
	pt := models.MustNewPoint(
		"cpu",
		models.Tags{{Key: []byte("host"), Value: []byte("server9999")}},
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err = sh.WritePoints([]models.Point{pt})
	if err == nil {
		t.Fatal("expected error")
	} else if exp, got := `partial write: max-values-per-tag limit exceeded (1000/1000): measurement="cpu" tag="host" value="server9999" dropped=1`, err.Error(); exp != got {
		t.Fatalf("unexpected error message:\n\texp = %s\n\tgot = %s", exp, got)
	}

	sh.Close()
}

func TestWriteTimeTag(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}
	defer sh.Close()

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{}),
		map[string]interface{}{"time": 1.0},
		time.Unix(1, 2),
	)

	if err := sh.WritePoints([]models.Point{pt}); err == nil {
		t.Fatal("expected error: got nil")
	}

	pt = models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{}),
		map[string]interface{}{"value": 1.0, "time": 1.0},
		time.Unix(1, 2),
	)

	if err := sh.WritePoints([]models.Point{pt}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mf := sh.MeasurementFields([]byte("cpu"))
	if mf == nil {
		t.Fatal("expected cpu measurement fields")
	}

	if got, exp := mf.FieldN(), 1; got != exp {
		t.Fatalf("invalid number of field names: got=%v exp=%v", got, exp)
	}
}

func TestWriteTimeField(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}
	defer sh.Close()

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"time": "now"}),
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	if err := sh.WritePoints([]models.Point{pt}); err == nil {
		t.Fatal("expected error: got nil")
	}

	key := models.MakeKey([]byte("cpu"), nil)
	if ok, err := sh.MeasurementExists(key); ok && err == nil {
		t.Fatal("unexpected series")
	}
}

func TestShardWriteAddNewField(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}
	defer sh.Close()

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"host": "server"}),
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err := sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}

	pt = models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"host": "server"}),
		map[string]interface{}{"value": 1.0, "value2": 2.0},
		time.Unix(1, 2),
	)

	err = sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}

	if got, exp := sh.SeriesN(), int64(1); got != exp {
		t.Fatalf("got %d series, exp %d series in index", got, exp)
	}
}

// Tests concurrently writing to the same shard with different field types which
// can trigger a panic when the shard is snapshotted to TSM files.
func TestShard_WritePoints_FieldConflictConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}
	defer sh.Close()

	points := make([]models.Point, 0, 1000)
	for i := 0; i < cap(points); i++ {
		if i < 500 {
			points = append(points, models.MustNewPoint(
				"cpu",
				models.NewTags(map[string]string{"host": "server"}),
				map[string]interface{}{"value": 1.0},
				time.Unix(int64(i), 0),
			))
		} else {
			points = append(points, models.MustNewPoint(
				"cpu",
				models.NewTags(map[string]string{"host": "server"}),
				map[string]interface{}{"value": int64(1)},
				time.Unix(int64(i), 0),
			))
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errC := make(chan error)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := sh.DeleteMeasurement([]byte("cpu")); err != nil {
				errC <- err
				return
			}

			_ = sh.WritePoints(points[:500])
			if f, err := sh.CreateSnapshot(); err == nil {
				os.RemoveAll(f)
			}

		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := sh.DeleteMeasurement([]byte("cpu")); err != nil {
				errC <- err
				return
			}

			_ = sh.WritePoints(points[500:])
			if f, err := sh.CreateSnapshot(); err == nil {
				os.RemoveAll(f)
			}
		}
	}()

	go func() {
		wg.Wait()
		close(errC)
	}()

	for err := range errC {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestShard_WritePoints_FieldConflictConcurrentQuery(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}
	defer sh.Close()

	// Spin up two goroutines that write points with different field types in reverse
	// order concurrently.  After writing them, query them back.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		// Write 250 floats and then ints to the same field
		points := make([]models.Point, 0, 500)
		for i := 0; i < cap(points); i++ {
			if i < 250 {
				points = append(points, models.MustNewPoint(
					"cpu",
					models.NewTags(map[string]string{"host": "server"}),
					map[string]interface{}{"value": 1.0},
					time.Unix(int64(i), 0),
				))
			} else {
				points = append(points, models.MustNewPoint(
					"cpu",
					models.NewTags(map[string]string{"host": "server"}),
					map[string]interface{}{"value": int64(1)},
					time.Unix(int64(i), 0),
				))
			}
		}

		for i := 0; i < 500; i++ {
			if err := sh.DeleteMeasurement([]byte("cpu")); err != nil {
				t.Fatalf(err.Error())
			}

			sh.WritePoints(points)

			iter, err := sh.CreateIterator("cpu", influxql.IteratorOptions{
				Expr:       influxql.MustParseExpr(`value`),
				Aux:        []influxql.VarRef{{Val: "value"}},
				Dimensions: []string{},
				Ascending:  true,
				StartTime:  influxql.MinTime,
				EndTime:    influxql.MaxTime,
			})
			if err != nil {
				t.Fatalf(err.Error())
			}

			switch itr := iter.(type) {
			case influxql.IntegerIterator:
				p, err := itr.Next()
				for p != nil && err == nil {
					p, err = itr.Next()
				}
				iter.Close()

			case influxql.FloatIterator:
				p, err := itr.Next()
				for p != nil && err == nil {
					p, err = itr.Next()
				}
				iter.Close()

			}

		}
	}()

	go func() {
		defer wg.Done()

		// Write 250 ints and then floats to the same field
		points := make([]models.Point, 0, 500)
		for i := 0; i < cap(points); i++ {
			if i < 250 {
				points = append(points, models.MustNewPoint(
					"cpu",
					models.NewTags(map[string]string{"host": "server"}),
					map[string]interface{}{"value": int64(1)},
					time.Unix(int64(i), 0),
				))
			} else {
				points = append(points, models.MustNewPoint(
					"cpu",
					models.NewTags(map[string]string{"host": "server"}),
					map[string]interface{}{"value": 1.0},
					time.Unix(int64(i), 0),
				))
			}
		}
		for i := 0; i < 500; i++ {
			if err := sh.DeleteMeasurement([]byte("cpu")); err != nil {
				t.Fatalf(err.Error())
			}

			sh.WritePoints(points)

			iter, err := sh.CreateIterator("cpu", influxql.IteratorOptions{
				Expr:       influxql.MustParseExpr(`value`),
				Aux:        []influxql.VarRef{{Val: "value"}},
				Dimensions: []string{},
				Ascending:  true,
				StartTime:  influxql.MinTime,
				EndTime:    influxql.MaxTime,
			})
			if err != nil {
				t.Fatalf(err.Error())
			}

			switch itr := iter.(type) {
			case influxql.IntegerIterator:
				p, err := itr.Next()
				for p != nil && err == nil {
					p, err = itr.Next()
				}
				iter.Close()
			case influxql.FloatIterator:
				p, err := itr.Next()
				for p != nil && err == nil {
					p, err = itr.Next()
				}
				iter.Close()
			}
		}
	}()

	wg.Wait()
}

// Ensures that when a shard is closed, it removes any series meta-data
// from the index.
func TestShard_Close_RemoveIndex(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "shard_test")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")

	opts := tsdb.NewEngineOptions()
	opts.Config.WALDir = filepath.Join(tmpDir, "wal")
	opts.InmemIndex = inmem.NewIndex(path.Base(tmpDir))

	sh := tsdb.NewShard(1, tmpShard, tmpWal, opts)
	if err := sh.Open(); err != nil {
		t.Fatalf("error opening shard: %s", err.Error())
	}

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"host": "server"}),
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err := sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf(err.Error())
	}

	if got, exp := sh.SeriesN(), int64(1); got != exp {
		t.Fatalf("got %d series, exp %d series in index", got, exp)
	}

	// ensure the index gets loaded after closing and opening the shard
	sh.Close()
	sh.Open()

	if got, exp := sh.SeriesN(), int64(1); got != exp {
		t.Fatalf("got %d series, exp %d series in index", got, exp)
	}
}

// Ensure a shard can create iterators for its underlying data.
func TestShard_CreateIterator_Ascending(t *testing.T) {
	sh := NewShard()

	// Calling CreateIterator when the engine is not open will return
	// ErrEngineClosed.
	_, got := sh.CreateIterator("cpu", influxql.IteratorOptions{})
	if exp := tsdb.ErrEngineClosed; got != exp {
		t.Fatalf("got %v, expected %v", got, exp)
	}

	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
`)

	// Create iterator.
	itr, err := sh.CreateIterator("cpu", influxql.IteratorOptions{
		Expr:       influxql.MustParseExpr(`value`),
		Aux:        []influxql.VarRef{{Val: "val2"}},
		Dimensions: []string{"host"},
		Ascending:  true,
		StartTime:  influxql.MinTime,
		EndTime:    influxql.MaxTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	fitr := itr.(influxql.FloatIterator)
	defer itr.Close()

	// Read values from iterator.
	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(0): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverA"}),
		Time:  time.Unix(0, 0).UnixNano(),
		Value: 100,
		Aux:   []interface{}{(*float64)(nil)},
	}) {
		t.Fatalf("unexpected point(0): %s", spew.Sdump(p))
	}

	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(1): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverA"}),
		Time:  time.Unix(10, 0).UnixNano(),
		Value: 50,
		Aux:   []interface{}{float64(5)},
	}) {
		t.Fatalf("unexpected point(1): %s", spew.Sdump(p))
	}

	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(2): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverB"}),
		Time:  time.Unix(0, 0).UnixNano(),
		Value: 25,
		Aux:   []interface{}{(*float64)(nil)},
	}) {
		t.Fatalf("unexpected point(2): %s", spew.Sdump(p))
	}
}

// Ensure a shard can create iterators for its underlying data.
func TestShard_CreateIterator_Descending(t *testing.T) {
	sh := NewShard()

	// Calling CreateIterator when the engine is not open will return
	// ErrEngineClosed.
	_, got := sh.CreateIterator("cpu", influxql.IteratorOptions{})
	if exp := tsdb.ErrEngineClosed; got != exp {
		t.Fatalf("got %v, expected %v", got, exp)
	}

	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
`)

	// Create iterator.
	itr, err := sh.CreateIterator("cpu", influxql.IteratorOptions{
		Expr:       influxql.MustParseExpr(`value`),
		Aux:        []influxql.VarRef{{Val: "val2"}},
		Dimensions: []string{"host"},
		Ascending:  false,
		StartTime:  influxql.MinTime,
		EndTime:    influxql.MaxTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer itr.Close()
	fitr := itr.(influxql.FloatIterator)

	// Read values from iterator.
	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(0): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverB"}),
		Time:  time.Unix(0, 0).UnixNano(),
		Value: 25,
		Aux:   []interface{}{(*float64)(nil)},
	}) {
		t.Fatalf("unexpected point(0): %s", spew.Sdump(p))
	}

	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(1): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverA"}),
		Time:  time.Unix(10, 0).UnixNano(),
		Value: 50,
		Aux:   []interface{}{float64(5)},
	}) {
		t.Fatalf("unexpected point(1): %s", spew.Sdump(p))
	}

	if p, err := fitr.Next(); err != nil {
		t.Fatalf("unexpected error(2): %s", err)
	} else if !deep.Equal(p, &influxql.FloatPoint{
		Name:  "cpu",
		Tags:  influxql.NewTags(map[string]string{"host": "serverA"}),
		Time:  time.Unix(0, 0).UnixNano(),
		Value: 100,
		Aux:   []interface{}{(*float64)(nil)},
	}) {
		t.Fatalf("unexpected point(2): %s", spew.Sdump(p))
	}
}

func TestShard_Disabled_WriteQuery(t *testing.T) {
	sh := NewShard()
	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.SetEnabled(false)

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"host": "server"}),
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	err := sh.WritePoints([]models.Point{pt})
	if err == nil {
		t.Fatalf("expected shard disabled error")
	}
	if err != tsdb.ErrShardDisabled {
		t.Fatalf(err.Error())
	}

	_, got := sh.CreateIterator("cpu", influxql.IteratorOptions{})
	if err == nil {
		t.Fatalf("expected shard disabled error")
	}
	if exp := tsdb.ErrShardDisabled; got != exp {
		t.Fatalf("got %v, expected %v", got, exp)
	}

	sh.SetEnabled(true)

	err = sh.WritePoints([]models.Point{pt})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err = sh.CreateIterator("cpu", influxql.IteratorOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", got)
	}
}

func TestShard_Closed_Functions(t *testing.T) {
	sh := NewShard()
	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	pt := models.MustNewPoint(
		"cpu",
		models.NewTags(map[string]string{"host": "server"}),
		map[string]interface{}{"value": 1.0},
		time.Unix(1, 2),
	)

	if err := sh.WritePoints([]models.Point{pt}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sh.Close()

	// Should not panic, just a no-op when shard is closed
	if err := sh.ForEachMeasurementTagKey([]byte("cpu"), func(k []byte) error {
		return nil
	}); err != nil {
		t.Fatalf("expected nil: got %v", err)
	}

	// Should not panic, just a no-op when shard is closed
	if exp, got := 0, sh.TagKeyCardinality([]byte("cpu"), []byte("host")); exp != got {
		t.Fatalf("expected nil: exp %v, got %v", exp, got)
	}
}

func TestShard_FieldDimensions(t *testing.T) {
	sh := NewShard()

	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
_reserved,region=uswest value="foo" 0
`)

	for _, tt := range []struct {
		sources []string
		f       map[string]influxql.DataType
		d       map[string]struct{}
	}{
		{
			sources: []string{"cpu"},
			f: map[string]influxql.DataType{
				"value": influxql.Float,
				"val2":  influxql.Float,
			},
			d: map[string]struct{}{
				"host":   {},
				"region": {},
			},
		},
		{
			sources: []string{"mem"},
			f: map[string]influxql.DataType{
				"value": influxql.Integer,
				"val3":  influxql.Boolean,
			},
			d: map[string]struct{}{
				"host": {},
			},
		},
		{
			sources: []string{"cpu", "mem"},
			f: map[string]influxql.DataType{
				"value": influxql.Float,
				"val2":  influxql.Float,
				"val3":  influxql.Boolean,
			},
			d: map[string]struct{}{
				"host":   {},
				"region": {},
			},
		},
		{
			sources: []string{"_fieldKeys"},
			f: map[string]influxql.DataType{
				"fieldKey":  influxql.String,
				"fieldType": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_series"},
			f: map[string]influxql.DataType{
				"key": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_tagKeys"},
			f: map[string]influxql.DataType{
				"tagKey": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_reserved"},
			f: map[string]influxql.DataType{
				"value": influxql.String,
			},
			d: map[string]struct{}{
				"region": {},
			},
		},
		{
			sources: []string{"unknown"},
			f:       map[string]influxql.DataType{},
			d:       map[string]struct{}{},
		},
	} {
		name := strings.Join(tt.sources, ",")
		t.Run(name, func(t *testing.T) {
			f, d, err := sh.FieldDimensions(tt.sources)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.f, f, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected fields:\n%s", diff)
			}
			if diff := cmp.Diff(tt.d, d, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected dimensions:\n%s", diff)
			}
		})
	}
}

func TestShard_MapType(t *testing.T) {
	sh := NewShard()

	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
_reserved,region=uswest value="foo" 0
`)

	for _, tt := range []struct {
		measurement string
		field       string
		typ         influxql.DataType
	}{
		{
			measurement: "cpu",
			field:       "value",
			typ:         influxql.Float,
		},
		{
			measurement: "cpu",
			field:       "host",
			typ:         influxql.Tag,
		},
		{
			measurement: "cpu",
			field:       "region",
			typ:         influxql.Tag,
		},
		{
			measurement: "cpu",
			field:       "val2",
			typ:         influxql.Float,
		},
		{
			measurement: "cpu",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "mem",
			field:       "value",
			typ:         influxql.Integer,
		},
		{
			measurement: "mem",
			field:       "val3",
			typ:         influxql.Boolean,
		},
		{
			measurement: "mem",
			field:       "host",
			typ:         influxql.Tag,
		},
		{
			measurement: "unknown",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_fieldKeys",
			field:       "fieldKey",
			typ:         influxql.String,
		},
		{
			measurement: "_fieldKeys",
			field:       "fieldType",
			typ:         influxql.String,
		},
		{
			measurement: "_fieldKeys",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_series",
			field:       "key",
			typ:         influxql.String,
		},
		{
			measurement: "_series",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_tagKeys",
			field:       "tagKey",
			typ:         influxql.String,
		},
		{
			measurement: "_tagKeys",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_reserved",
			field:       "value",
			typ:         influxql.String,
		},
		{
			measurement: "_reserved",
			field:       "region",
			typ:         influxql.Tag,
		},
	} {
		name := fmt.Sprintf("%s - %s", tt.measurement, tt.field)
		t.Run(name, func(t *testing.T) {
			typ := sh.MapType(tt.measurement, tt.field)
			if have, want := typ, tt.typ; have != want {
				t.Errorf("unexpected data type: have=%#v want=%#v", have, want)
			}
		})
	}
}

func TestShard_MeasurementsByRegex(t *testing.T) {
	sh := NewShard()

	if err := sh.Open(); err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	sh.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
`)

	for _, tt := range []struct {
		regex        string
		measurements []string
	}{
		{regex: `cpu`, measurements: []string{"cpu"}},
		{regex: `mem`, measurements: []string{"mem"}},
		{regex: `cpu|mem`, measurements: []string{"cpu", "mem"}},
		{regex: `gpu`, measurements: []string{}},
		{regex: `pu`, measurements: []string{"cpu"}},
		{regex: `p|m`, measurements: []string{"cpu", "mem"}},
	} {
		t.Run(tt.regex, func(t *testing.T) {
			re := regexp.MustCompile(tt.regex)
			measurements := sh.MeasurementsByRegex(re)
			sort.Strings(measurements)
			if diff := cmp.Diff(tt.measurements, measurements, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected measurements:\n%s", diff)
			}
		})
	}
}

func TestShards_FieldDimensions(t *testing.T) {
	shard1 := NewShard()

	if err := shard1.Open(); err != nil {
		t.Fatal(err)
	}
	defer shard1.Close()

	shard1.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
`)

	shard2 := NewShard()

	if err := shard2.Open(); err != nil {
		t.Fatal(err)
	}

	shard2.MustWritePointsString(`
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
_reserved,region=uswest value="foo" 0
`)

	sh := tsdb.Shards([]*tsdb.Shard{shard1.Shard, shard2.Shard})
	for _, tt := range []struct {
		sources []string
		f       map[string]influxql.DataType
		d       map[string]struct{}
	}{
		{
			sources: []string{"cpu"},
			f: map[string]influxql.DataType{
				"value": influxql.Float,
				"val2":  influxql.Float,
			},
			d: map[string]struct{}{
				"host":   {},
				"region": {},
			},
		},
		{
			sources: []string{"mem"},
			f: map[string]influxql.DataType{
				"value": influxql.Integer,
				"val3":  influxql.Boolean,
			},
			d: map[string]struct{}{
				"host": {},
			},
		},
		{
			sources: []string{"cpu", "mem"},
			f: map[string]influxql.DataType{
				"value": influxql.Float,
				"val2":  influxql.Float,
				"val3":  influxql.Boolean,
			},
			d: map[string]struct{}{
				"host":   {},
				"region": {},
			},
		},
		{
			sources: []string{"_fieldKeys"},
			f: map[string]influxql.DataType{
				"fieldKey":  influxql.String,
				"fieldType": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_series"},
			f: map[string]influxql.DataType{
				"key": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_tagKeys"},
			f: map[string]influxql.DataType{
				"tagKey": influxql.String,
			},
			d: map[string]struct{}{},
		},
		{
			sources: []string{"_reserved"},
			f: map[string]influxql.DataType{
				"value": influxql.String,
			},
			d: map[string]struct{}{
				"region": {},
			},
		},
		{
			sources: []string{"unknown"},
			f:       map[string]influxql.DataType{},
			d:       map[string]struct{}{},
		},
	} {
		name := strings.Join(tt.sources, ",")
		t.Run(name, func(t *testing.T) {
			f, d, err := sh.FieldDimensions(tt.sources)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.f, f, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected fields:\n%s", diff)
			}
			if diff := cmp.Diff(tt.d, d, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected dimensions:\n%s", diff)
			}
		})
	}
}

func TestShards_MapType(t *testing.T) {
	shard1 := NewShard()

	if err := shard1.Open(); err != nil {
		t.Fatal(err)
	}
	defer shard1.Close()

	shard1.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
`)

	shard2 := NewShard()

	if err := shard2.Open(); err != nil {
		t.Fatal(err)
	}

	shard2.MustWritePointsString(`
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
_reserved,region=uswest value="foo" 0
`)

	sh := tsdb.Shards([]*tsdb.Shard{shard1.Shard, shard2.Shard})
	for _, tt := range []struct {
		measurement string
		field       string
		typ         influxql.DataType
	}{
		{
			measurement: "cpu",
			field:       "value",
			typ:         influxql.Float,
		},
		{
			measurement: "cpu",
			field:       "host",
			typ:         influxql.Tag,
		},
		{
			measurement: "cpu",
			field:       "region",
			typ:         influxql.Tag,
		},
		{
			measurement: "cpu",
			field:       "val2",
			typ:         influxql.Float,
		},
		{
			measurement: "cpu",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "mem",
			field:       "value",
			typ:         influxql.Integer,
		},
		{
			measurement: "mem",
			field:       "val3",
			typ:         influxql.Boolean,
		},
		{
			measurement: "mem",
			field:       "host",
			typ:         influxql.Tag,
		},
		{
			measurement: "unknown",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_fieldKeys",
			field:       "fieldKey",
			typ:         influxql.String,
		},
		{
			measurement: "_fieldKeys",
			field:       "fieldType",
			typ:         influxql.String,
		},
		{
			measurement: "_fieldKeys",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_series",
			field:       "key",
			typ:         influxql.String,
		},
		{
			measurement: "_series",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_tagKeys",
			field:       "tagKey",
			typ:         influxql.String,
		},
		{
			measurement: "_tagKeys",
			field:       "unknown",
			typ:         influxql.Unknown,
		},
		{
			measurement: "_reserved",
			field:       "value",
			typ:         influxql.String,
		},
		{
			measurement: "_reserved",
			field:       "region",
			typ:         influxql.Tag,
		},
	} {
		name := fmt.Sprintf("%s - %s", tt.measurement, tt.field)
		t.Run(name, func(t *testing.T) {
			typ := sh.MapType(tt.measurement, tt.field)
			if have, want := typ, tt.typ; have != want {
				t.Errorf("unexpected data type: have=%#v want=%#v", have, want)
			}
		})
	}
}

func TestShards_MeasurementsByRegex(t *testing.T) {
	shard1 := NewShard()

	if err := shard1.Open(); err != nil {
		t.Fatal(err)
	}
	defer shard1.Close()

	shard1.MustWritePointsString(`
cpu,host=serverA,region=uswest value=100 0
cpu,host=serverA,region=uswest value=50,val2=5  10
cpu,host=serverB,region=uswest value=25  0
`)

	shard2 := NewShard()

	if err := shard2.Open(); err != nil {
		t.Fatal(err)
	}

	shard2.MustWritePointsString(`
mem,host=serverA value=25i 0
mem,host=serverB value=50i,val3=t 10
_reserved,region=uswest value="foo" 0
`)

	sh := tsdb.Shards([]*tsdb.Shard{shard1.Shard, shard2.Shard})
	for _, tt := range []struct {
		regex        string
		measurements []string
	}{
		{regex: `cpu`, measurements: []string{"cpu"}},
		{regex: `mem`, measurements: []string{"mem"}},
		{regex: `cpu|mem`, measurements: []string{"cpu", "mem"}},
		{regex: `gpu`, measurements: []string{}},
		{regex: `pu`, measurements: []string{"cpu"}},
		{regex: `p|m`, measurements: []string{"cpu", "mem"}},
	} {
		t.Run(tt.regex, func(t *testing.T) {
			re := regexp.MustCompile(tt.regex)
			measurements := sh.MeasurementsByRegex(re)
			sort.Strings(measurements)
			if diff := cmp.Diff(tt.measurements, measurements, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected measurements:\n%s", diff)
			}
		})
	}
}

func BenchmarkWritePoints_NewSeries_1K(b *testing.B)   { benchmarkWritePoints(b, 38, 3, 3, 1) }
func BenchmarkWritePoints_NewSeries_100K(b *testing.B) { benchmarkWritePoints(b, 32, 5, 5, 1) }
func BenchmarkWritePoints_NewSeries_250K(b *testing.B) { benchmarkWritePoints(b, 80, 5, 5, 1) }
func BenchmarkWritePoints_NewSeries_500K(b *testing.B) { benchmarkWritePoints(b, 160, 5, 5, 1) }
func BenchmarkWritePoints_NewSeries_1M(b *testing.B)   { benchmarkWritePoints(b, 320, 5, 5, 1) }

// Fix measurement and tag key cardinalities and vary tag value cardinality
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_100_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 100, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_500_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 500, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_1000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 1000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_5000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 5000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_10000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 10000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_50000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 50000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_100000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 100000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_500000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 500000, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_1000000_TagValues(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 1000000, 1)
}

// Fix tag key and tag values cardinalities and vary measurement cardinality
func BenchmarkWritePoints_NewSeries_100_Measurements_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 100, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_500_Measurements_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 500, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1000, 1, 1, 1)
}

func BenchmarkWritePoints_NewSeries_5000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 5000, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_10000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 10000, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_50000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 50000, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_100000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 100000, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_500000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 500000, 1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1000000_Measurement_1_TagKey_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1000000, 1, 1, 1)
}

// Fix measurement and tag values cardinalities and vary tag key cardinality
func BenchmarkWritePoints_NewSeries_1_Measurement_2_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<1, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurements_4_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<2, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurements_8_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<3, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_16_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<4, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_32_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<5, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_64_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<6, 1, 1)

}
func BenchmarkWritePoints_NewSeries_1_Measurement_128_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<7, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_256_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<8, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_512_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<9, 1, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_1024_TagKeys_1_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1<<10, 1, 1)
}

// Fix series cardinality and vary tag keys and value cardinalities
func BenchmarkWritePoints_NewSeries_1_Measurement_1_TagKey_65536_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 1, 1<<16, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_2_TagKeys_256_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 2, 1<<8, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_4_TagKeys_16_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 4, 1<<4, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_8_TagKeys_4_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 8, 1<<2, 1)
}
func BenchmarkWritePoints_NewSeries_1_Measurement_16_TagKeys_2_TagValue(b *testing.B) {
	benchmarkWritePoints(b, 1, 16, 1<<1, 1)
}

func BenchmarkWritePoints_ExistingSeries_1K(b *testing.B) {
	benchmarkWritePointsExistingSeries(b, 38, 3, 3, 1)
}
func BenchmarkWritePoints_ExistingSeries_100K(b *testing.B) {
	benchmarkWritePointsExistingSeries(b, 32, 5, 5, 1)
}
func BenchmarkWritePoints_ExistingSeries_250K(b *testing.B) {
	benchmarkWritePointsExistingSeries(b, 80, 5, 5, 1)
}
func BenchmarkWritePoints_ExistingSeries_500K(b *testing.B) {
	benchmarkWritePointsExistingSeries(b, 160, 5, 5, 1)
}
func BenchmarkWritePoints_ExistingSeries_1M(b *testing.B) {
	benchmarkWritePointsExistingSeries(b, 320, 5, 5, 1)
}

// benchmarkWritePoints benchmarks writing new series to a shard.
// mCnt - measurement count
// tkCnt - tag key count
// tvCnt - tag value count (values per tag)
// pntCnt - points per series.  # of series = mCnt * (tvCnt ^ tkCnt)
func benchmarkWritePoints(b *testing.B, mCnt, tkCnt, tvCnt, pntCnt int) {
	// Generate test series (measurements + unique tag sets).
	series := genTestSeries(mCnt, tkCnt, tvCnt)
	// Generate point data to write to the shard.
	points := []models.Point{}
	for _, s := range series {
		for val := 0.0; val < float64(pntCnt); val++ {
			p := models.MustNewPoint(s.Measurement, s.Series.Tags(), map[string]interface{}{"value": val}, time.Now())
			points = append(points, p)
		}
	}

	// Stop & reset timers and mem-stats before the main benchmark loop.
	b.StopTimer()
	b.ResetTimer()

	// Run the benchmark loop.
	for n := 0; n < b.N; n++ {
		tmpDir, _ := ioutil.TempDir("", "shard_test")
		tmpShard := path.Join(tmpDir, "shard")
		tmpWal := path.Join(tmpDir, "wal")
		shard := tsdb.NewShard(1, tmpShard, tmpWal, tsdb.NewEngineOptions())
		shard.Open()

		b.StartTimer()
		// Call the function being benchmarked.
		chunkedWrite(shard, points)

		b.StopTimer()
		shard.Close()
		os.RemoveAll(tmpDir)
	}
}

// benchmarkWritePointsExistingSeries benchmarks writing to existing series in a shard.
// mCnt - measurement count
// tkCnt - tag key count
// tvCnt - tag value count (values per tag)
// pntCnt - points per series.  # of series = mCnt * (tvCnt ^ tkCnt)
func benchmarkWritePointsExistingSeries(b *testing.B, mCnt, tkCnt, tvCnt, pntCnt int) {
	// Generate test series (measurements + unique tag sets).
	series := genTestSeries(mCnt, tkCnt, tvCnt)
	// Generate point data to write to the shard.
	points := []models.Point{}
	for _, s := range series {
		for val := 0.0; val < float64(pntCnt); val++ {
			p := models.MustNewPoint(s.Measurement, s.Series.Tags(), map[string]interface{}{"value": val}, time.Now())
			points = append(points, p)
		}
	}

	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)
	tmpShard := path.Join(tmpDir, "shard")
	tmpWal := path.Join(tmpDir, "wal")
	shard := tsdb.NewShard(1, tmpShard, tmpWal, tsdb.NewEngineOptions())
	shard.Open()
	defer shard.Close()
	chunkedWrite(shard, points)

	// Reset timers and mem-stats before the main benchmark loop.
	b.ResetTimer()

	// Run the benchmark loop.
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		for _, p := range points {
			p.SetTime(p.Time().Add(time.Second))
		}

		b.StartTimer()
		// Call the function being benchmarked.
		chunkedWrite(shard, points)
	}
}

func chunkedWrite(shard *tsdb.Shard, points []models.Point) {
	nPts := len(points)
	chunkSz := 10000
	start := 0
	end := chunkSz

	for {
		if end > nPts {
			end = nPts
		}
		if end-start == 0 {
			break
		}

		shard.WritePoints(points[start:end])
		start = end
		end += chunkSz
	}
}

// Shard represents a test wrapper for tsdb.Shard.
type Shard struct {
	*tsdb.Shard
	path string
}

// NewShard returns a new instance of Shard with temp paths.
func NewShard() *Shard {
	// Create temporary path for data and WAL.
	dir, err := ioutil.TempDir("", "influxdb-tsdb-")
	if err != nil {
		panic(err)
	}

	// Build engine options.
	opt := tsdb.NewEngineOptions()
	opt.Config.WALDir = filepath.Join(dir, "wal")
	opt.InmemIndex = inmem.NewIndex(path.Base(dir))

	return &Shard{
		Shard: tsdb.NewShard(0,
			filepath.Join(dir, "data", "db0", "rp0", "1"),
			filepath.Join(dir, "wal", "db0", "rp0", "1"),
			opt,
		),
		path: dir,
	}
}

// Close closes the shard and removes all underlying data.
func (sh *Shard) Close() error {
	defer os.RemoveAll(sh.path)
	return sh.Shard.Close()
}

// MustWritePointsString parses the line protocol (with second precision) and
// inserts the resulting points into the shard. Panic on error.
func (sh *Shard) MustWritePointsString(s string) {
	a, err := models.ParsePointsWithPrecision([]byte(strings.TrimSpace(s)), time.Time{}, "s")
	if err != nil {
		panic(err)
	}

	if err := sh.WritePoints(a); err != nil {
		panic(err)
	}
}
