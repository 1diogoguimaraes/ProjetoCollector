    //////////////////////////////////////////////
    // DROPDOWN IMAGE PROFILE
    // Logout
    const profileImg = document.getElementById('profileImg');
    const profileDropdown = document.getElementById('profileDropdown');

    profileImg.addEventListener('click', () => {
      profileDropdown.style.display = profileDropdown.style.display === 'block' ? 'none' : 'block';
    });

    // Hide dropdown when clicking outside
    document.addEventListener('click', (event) => {
      if (!profileImg.contains(event.target) && !profileDropdown.contains(event.target)) {
        profileDropdown.style.display = 'none';
      }
    });

    // Hook logout from dropdown
    document.getElementById('logoutBtnDropdown').addEventListener('click', (e) => {
      e.preventDefault(); // Prevent default action of the link

      // Show the custom modal
      const logoutModal = document.getElementById('logoutModal');
      logoutModal.style.display = 'flex';
    });

    // Handle confirm logout
    document.getElementById('confirmLogout').addEventListener('click', async () => {
      await fetch('/logout', { method: 'POST' });
      window.location.href = '/login';
    });

    // Handle cancel logout
    document.getElementById('cancelLogout').addEventListener('click', () => {
      const logoutModal = document.getElementById('logoutModal');
      logoutModal.style.display = 'none'; // Close the modal
    });

    // Close the modal if the user clicks outside of it
    window.addEventListener('click', (event) => {
      const logoutModal = document.getElementById('logoutModal');
      if (event.target === logoutModal) {
        logoutModal.style.display = 'none'; // Close the modal if clicked outside
      }
    });
    ////////////////////////////////////////////
    