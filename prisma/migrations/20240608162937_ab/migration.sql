/*
  Warnings:

  - Changed the type of `userId` on the `refreshtokens` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "refreshtokens" DROP COLUMN "userId",
ADD COLUMN     "userId" INTEGER NOT NULL;
