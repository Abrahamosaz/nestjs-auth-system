/*
  Warnings:

  - You are about to drop the column `expireDate` on the `refreshtokens` table. All the data in the column will be lost.
  - Added the required column `expiryDate` to the `refreshtokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "refreshtokens" DROP COLUMN "expireDate",
ADD COLUMN     "expiryDate" TIMESTAMP(3) NOT NULL;
