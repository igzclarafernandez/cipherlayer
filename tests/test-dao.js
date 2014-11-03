var dao = require('../dao.js');
var assert = require('assert');

describe('user dao', function(){

    var users = [
        {
            username:'user1',
            password:'pass1'
        }
    ];

    beforeEach(function(done){
        dao.deleteAllUsers(done);
    });

    it('count', function(done){
        dao.countUsers(function(err,count){
            assert.equal(err, null);
            assert.equal(count, 0);
            done();
        });
    });

    it('add', function(done){
        var expectedUser = users[0];
        dao.addUser(expectedUser.username,expectedUser.password,function(err,createdUser){
            assert.equal(err,null);
            assert.equal(createdUser.username,expectedUser.username);
            assert.equal(createdUser.password,expectedUser.password);
            dao.countUsers(function(err,count){
                assert.equal(err, null);
                assert.equal(count, 1);
                done();
            });
        });
    });

    it('already exists', function(done){
        var expectedUser = users[0];
        dao.addUser(expectedUser.username,expectedUser.password,function(err,createdUser){
            assert.equal(err,null);
            assert.equal(createdUser.username,expectedUser.username);
            assert.equal(createdUser.password,expectedUser.password);
            dao.addUser(expectedUser.username,expectedUser.password,function(err,createdUser){
                assert.equal(err.message,'username_already_exists');
                assert.equal(createdUser,null);
                done();
            });
        });

    });

    it('getFromUsernamePassword', function(done){
        var expectedUser = users[0];
        dao.addUser(expectedUser.username,expectedUser.password,function(err,createdUser){
            assert.equal(err,null);
            assert.notEqual(createdUser,null);
            dao.getFromUsernamePassword(expectedUser.username, expectedUser.password, function(err, foundUser){
                assert.equal(err,null);
                assert.equal(foundUser.username,expectedUser.username);
                assert.equal(foundUser.password,expectedUser.password);
                done();
            });
        });
    });

    it('delete all', function(done){
        dao.deleteAllUsers(function(err){
            assert.equal(err,null);
            dao.countUsers(function(err,count){
                assert.equal(err, null);
                assert.equal(count, 0);
                done();
            });
        }) ;
    });
});