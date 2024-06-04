const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function seed() {
  try {
    const hashedPassword = '$2b$10$LBwC5tF0/fuCDKu7mzpEru6Pz7k0Y1v/6nGiUPZyBxznbyqCDc9xq';

    await prisma.user.create({
      data: {
        username: 'user1',
        password: hashedPassword,
      },
    });

    console.log('User seeder completed successfully!');
  } catch (error) {
    console.error('Error seeding user:', error);
  } finally {
    await prisma.$disconnect();
  }
}

seed();
