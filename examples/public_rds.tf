resource "aws_db_instance" "production_db" {

  identifier = "production-db"

  engine = "mysql"

  instance_class = "db.t3.micro"

  allocated_storage = 20

  username = "admin"

  password = "Password123!"

  publicly_accessible = true

}