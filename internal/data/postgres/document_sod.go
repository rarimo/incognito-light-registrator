package data

import (
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"github.com/fatih/structs"
	"github.com/rarimo/passport-identity-provider/internal/data"
	"gitlab.com/distributed_lab/kit/pgdb"
)

const documentSODTableName = "document_sod"

var (
	documentSODSelector = sq.Select("*").From(documentSODTableName)
	documentSODUpdate   = sq.Update(documentSODTableName)
)

func NewDocumentSODQ(db *pgdb.DB) data.DocumentSODQ {
	return &DocumentSODQ{
		db:  db,
		sql: documentSODSelector,
		upd: documentSODUpdate,
	}
}

type DocumentSODQ struct {
	db  *pgdb.DB
	sql sq.SelectBuilder
	upd sq.UpdateBuilder
}

func (q *DocumentSODQ) ResetFilters() data.DocumentSODQ {
	q.sql = documentSODSelector
	q.upd = documentSODUpdate
	return q
}

func (q *DocumentSODQ) New() data.DocumentSODQ {
	return NewDocumentSODQ(q.db.Clone())
}

func (q *DocumentSODQ) Get() (*data.DocumentSOD, error) {
	var result data.DocumentSOD

	err := q.db.Get(&result, q.sql)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	return &result, err
}

func (q *DocumentSODQ) Select() ([]data.DocumentSOD, error) {
	var result []data.DocumentSOD

	err := q.db.Select(&result, q.sql)

	return result, err
}

func (q *DocumentSODQ) Upsert(value data.DocumentSOD) (*data.DocumentSOD, error) {
	var result data.DocumentSOD
	clauses := structs.Map(value)
	stmt := sq.Insert(documentSODTableName).SetMap(clauses).Suffix(
		"on conflict (hash) do update set updated_at = current_timestamp returning *",
	)
	err := q.db.Get(&result, stmt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	return &result, err
}
