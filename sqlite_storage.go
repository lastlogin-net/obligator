package main

//import (
//	"fmt"
//	"os"
//
//	"github.com/jmoiron/sqlx"
//	"github.com/mattn/go-sqlite3"
//)
//
//type SqliteStorage struct {
//	db *sqlx.DB
//}
//
//func NewSqliteStorage(path string) (*SqliteStorage, error) {
//
//	db, err := sqlx.Open("sqlite3", path)
//	if err != nil {
//		return nil, err
//	}
//
//	stmt := `
//        create table users (id integer not null primary key, email TEXT NOT NULL UNIQUE);
//        `
//	_, err = db.Exec(stmt)
//	if sqliteErr, ok := err.(sqlite3.Error); ok {
//		if sqliteErr.Code != sqlite3.ErrError {
//			return nil, err
//		}
//	}
//
//	stmt = `
//        create table oauth2_providers (id TEXT NOT NULL PRIMARY KEY, name TEXT,
//                uri TEXT, client_id TEXT, client_secret TEXT,
//                authorization_uri TEXT, token_uri TEXT, scope TEXT,
//                supports_openid_connect BOOLEAN);
//        `
//	_, err = db.Exec(stmt)
//	if sqliteErr, ok := err.(sqlite3.Error); ok {
//		if sqliteErr.Code != sqlite3.ErrError {
//			return nil, err
//		}
//	}
//
//	stmt = `
//        create table root_uri (id integer not null primary key, root_uri text);
//        `
//	_, err = db.Exec(stmt)
//	if sqliteErr, ok := err.(sqlite3.Error); ok {
//		if sqliteErr.Code != sqlite3.ErrError {
//			return nil, err
//		}
//	}
//
//	stmt = `
//        insert into root_uri values(0, "");
//        `
//	_, err = db.Exec(stmt)
//	if sqliteErr, ok := err.(sqlite3.Error); ok {
//		if sqliteErr.Code != sqlite3.ErrConstraint {
//			return nil, err
//		}
//	}
//
//	s := &SqliteStorage{
//		db: db,
//	}
//
//	return s, nil
//}
//
//func (s *SqliteStorage) GetRootUri() string {
//	var rootUri string
//	err := s.db.QueryRow("select root_uri from root_uri where id=0").Scan(&rootUri)
//	// TODO: handle errors
//	if err != nil {
//		fmt.Fprintln(os.Stderr, err)
//	}
//	return rootUri
//}
//
//func (s *SqliteStorage) SetRootUri(rootUri string) error {
//	stmt := `
//        update root_uri set root_uri = ?;
//        `
//	_, err := s.db.Exec(stmt, rootUri)
//	if err != nil {
//		fmt.Fprintln(os.Stderr, err)
//	}
//	return nil
//}
//
//func (s *SqliteStorage) GetUsers() ([]User, error) {
//	rows, err := s.db.Query("select email from users")
//	if err != nil {
//		return []User{}, err
//	}
//	defer rows.Close()
//
//	users := []User{}
//
//	for rows.Next() {
//		var user User
//		err = rows.Scan(&user.Email)
//		if err != nil {
//			return []User{}, err
//		}
//		users = append(users, user)
//	}
//	err = rows.Err()
//	if err != nil {
//		return []User{}, err
//	}
//
//	return users, nil
//}
//
//func (s *SqliteStorage) CreateUser(user User) error {
//	stmt := `
//        INSERT INTO users (email) VALUES(?);
//        `
//	_, err := s.db.Exec(stmt, user.Email)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func (s *SqliteStorage) GetOAuth2Providers() ([]OAuth2Provider, error) {
//	rows, err := s.db.Queryx("SELECT * FROM oauth2_providers")
//	if err != nil {
//		return []OAuth2Provider{}, err
//	}
//	defer rows.Close()
//
//	providers := []OAuth2Provider{}
//
//	for rows.Next() {
//		var p OAuth2Provider
//		err = rows.StructScan(&p)
//		if err != nil {
//			return []OAuth2Provider{}, err
//		}
//		providers = append(providers, p)
//	}
//	err = rows.Err()
//	if err != nil {
//		return []OAuth2Provider{}, err
//	}
//
//	return providers, nil
//}
//
//func (s *SqliteStorage) GetOAuth2ProviderByID(id string) (OAuth2Provider, error) {
//	var provider OAuth2Provider
//	err := s.db.Get(&provider, "SELECT * FROM oauth2_providers WHERE id=?", id)
//	if err != nil {
//		return OAuth2Provider{}, err
//	}
//	return provider, nil
//}
//
//func (s *SqliteStorage) SetOauth2Provider(provider OAuth2Provider) error {
//	stmt := `INSERT INTO oauth2_providers
//        (id,name,uri,client_id,client_secret,authorization_uri,token_uri,scope,supports_openid_connect)
//        VALUES
//        (:id,:name,:uri,:client_id,:client_secret,:authorization_uri,:token_uri,:scope,:supports_openid_connect)
//        `
//
//	_, err := s.db.NamedExec(stmt, &provider)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (s *SqliteStorage) GetPublic() bool {
//	panic("not implemented")
//	return false
//}
//
//func (s *SqliteStorage) AddLoginData() (string, error) {
//	panic("not implemented")
//	return "", nil
//}
//
//func (s *SqliteStorage) EnsureIdentity(providerId, providerName, email string) (string, error) {
//	panic("not implemented")
//	return "", nil
//}
//
//func (s *SqliteStorage) EnsureLoginMapping(identityId, loginKey string) {
//	panic("not implemented")
//}
