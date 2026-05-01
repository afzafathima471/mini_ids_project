#!/usr/bin/env python
from app import app

with app.test_client() as c:
    # Login
    c.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    
    # Test dashboard
    rv = c.get('/dashboard')
    print(f'Dashboard Status: {rv.status_code}')
    
    if rv.status_code == 200:
        print('✓ Dashboard route working correctly!')
    else:
        print(f'✗ Dashboard error: {rv.data.decode()[:500]}')
