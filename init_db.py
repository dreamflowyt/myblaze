from app import app, db

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        print("Dropped all tables")
        
        # Create all tables
        db.create_all()
        print("Created all tables")
        
        print("Database initialized successfully!")

if __name__ == "__main__":
    init_db() 