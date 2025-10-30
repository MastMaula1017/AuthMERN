import React from 'react';
import { Link } from 'react-router-dom';

const Navbar = () => {
    const handleLogout = () => {
        // Logic to handle logout
        console.log("User logged out");
    };

    return (
        <nav>
            <ul>
                <li><Link to="/">Home</Link></li>
                <li><Link to="/about">About</Link></li>
                <li><Link to="/dashboard">Dashboard</Link></li>
                <li><button onClick={handleLogout}>Logout</button></li>
            </ul>
        </nav>
    );
};

export default Navbar;