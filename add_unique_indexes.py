import sqlite3

db = sqlite3.connect("auth.db")
cur = db.cursor()

# stats table
cur.execute("""
  CREATE UNIQUE INDEX IF NOT EXISTS uq_stats_user_world_save
    ON stats(user_id, world_key, save_key);
""")

# quests table
cur.execute("""
  CREATE UNIQUE INDEX IF NOT EXISTS uq_quests_user_world_save
    ON quests(user_id, world_key, save_key);
""")

# inventory table
cur.execute("""
  CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_user_world_save
    ON inventory(user_id, world_key, save_key);
""")

# characters table (make sure you’ve added the save_key column first!)
cur.execute("""
  CREATE UNIQUE INDEX IF NOT EXISTS uq_characters_user_world_save
    ON characters(user_id, world_key, save_key);
""")

db.commit()
db.close()
