-- Role
INSERT INTO role(name, authority) VALUES ('user', 'ROLE_USER');
INSERT INTO role(name, authority) VALUES ('admin', 'ROLE_USER');
INSERT INTO role(name, authority) VALUES ('admin', 'ROLE_ADMIN');

-- Grade
INSERT INTO grade(name, accumulation_rate, description) VALUES ('BASIC', 1, '결제 시 순수금액의 1% 포인트 정립');
INSERT INTO grade(name, accumulation_rate, description) VALUES ('SILVER', 3, '결제 시 순수금액의 3% 포인트 정립');
INSERT INTO grade(name, accumulation_rate, description) VALUES ('GOLD', 5, '결제 시 순수금액의 5% 포인트 정립');
INSERT INTO grade(name, accumulation_rate, description) VALUES ('VIP', 7, '결제 시 순수금액의 7% 포인트 정립');
