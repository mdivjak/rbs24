insert into users(id, username, password)
values (1, 'bruce', 'wayne'),
       (2, 'peter', 'security_rules'),
       (3, 'tom', 'guessmeifyoucan'),
        (4, 'santa', 'clause');

insert into persons(id, firstName, lastName, email)
values (1, 'bruce', 'wayne', 'notBatman@gmail.com'),
       (2, 'Peter', 'Petigrew', 'oneFingernailFewerToClean@gmail.com'),
       (3, 'Tom', 'Riddle', 'theyGotMyNose@gmail.com'),
        (4, 'Santa', 'Clause', 'st@northPole.com');

insert into gift(id, name, description, price)
values (1, 'Christmas tree decoration', 'Decoration for a Christmas tree', 500.01),
       (2, 'Christmas tree', 'A fake christmas tree', 1500.99),
       (3, 'Santa Clause', 'A small Santa Clause for decoration', 750.00),
       (4, 'Sweater', 'New Year sweater', 3000.00);

insert into tags(id, name)
values (1, 'small'),
       (2, 'big'),
       (3, 'wholesome'),
       (4, 'clothing'),
       (5, 'toy'),
       (6, 'doll'),
       (7, 'car');

insert into gift_to_tag(giftId, tagId)
values (1, 1),
       (1, 3),
       (2, 2),
       (2, 3),
       (3, 1),
       (3, 3),
       (4, 4);

insert into ratings(giftId, userId, rating)
values (1, 3, 5),
        (3, 2, 1),
        (3, 1, 3),
        (1, 1, 5),
        (1, 2, 4);

insert into comments(giftId, userId, comment)
values (1, 1, 'Very nice.');

insert into roles(id, name)
values (1, 'ADMIN'),
       (2, 'MANAGER'),
       (3, 'BUYER');

insert into user_to_roles(userId, roleId)
values (4, 1), --santa, admin
       (3, 2), --tom, manager
       (1, 3), --bruce, buyer
       (2, 3); --peter, buyer

insert into permissions(id, name)
values (1, 'ADD_COMMENT'),
       (2, 'VIEW_GIFT_LIST'),
       (3, 'CREATE_GIFT'),
       (4, 'VIEW_PERSONS_LIST'),
       (5, 'VIEW_PERSON'),
       (6, 'UPDATE_PERSON'),
       (7, 'VIEW_MY_PROFILE'),
       (8, 'RATE_GIFT'),
       (9, 'BUY_GIFT');

insert into role_to_permissions(roleId, permissionId)
values
    --ADMIN
    (1, 1),
    (1, 2),
    (1, 3),
    (1, 4),
    (1, 5),
    (1, 6),
    (1, 7),
    (1, 8),
    (1, 9),
    --MANAGER
    (2, 1),
    (2, 2),
    (2, 3),
    (2, 4),
    (2, 6),
    (2, 7),
    (2, 9),
    --BUYER
    (3, 1),
    (3, 2),
    (3, 6),
    (3, 7),
    (3, 8),
    (3, 9);

