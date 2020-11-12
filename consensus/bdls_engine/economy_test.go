package bdls_engine

import (
	fmt "fmt"
	"testing"

	"github.com/Sperax/SperaxChain/common"
	"github.com/Sperax/SperaxChain/core/rawdb"
	"github.com/Sperax/SperaxChain/core/state"
	"github.com/Sperax/SperaxChain/ethdb"
	"github.com/stretchr/testify/assert"
)

type stateTest struct {
	db    ethdb.Database
	state *state.StateDB
}

func newStateTest() *stateTest {
	db := rawdb.NewMemoryDatabase()
	sdb, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	return &stateTest{db: db, state: sdb}
}

func TestStatsVariables(t *testing.T) {
	s := newStateTest()

	// total validator rewards distributed
	totalValidatorRewards := getTotalValidatorRewards(s.state)
	totalValidatorRewards.Add(totalValidatorRewards, TotalValidatorReward)
	setTotalValidatorRewards(totalValidatorRewards, s.state)

	finalReward := getTotalValidatorRewards(s.state)
	assert.EqualValues(t, finalReward, totalValidatorRewards)

	// per account block rewards statistics
	address := GasFeeAddress
	accountBlockRewards := getMapValue(address, KeyAccountValidatorRewards, s.state).Big()
	accountBlockRewards.Add(accountBlockRewards, TotalValidatorReward)
	setMapValue(address, KeyAccountValidatorRewards, common.BigToHash(accountBlockRewards), s.state)

	final := getMapValue(address, KeyAccountValidatorRewards, s.state).Big()
	assert.EqualValues(t, final, accountBlockRewards)

	t.Log(fmt.Sprintf(KeyAccountValidatorRewards, address.String()))
}
