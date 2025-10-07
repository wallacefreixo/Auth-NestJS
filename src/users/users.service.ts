import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { Users } from './users.entity';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(Users)
    private repo: Repository<Users>,
  ) {}

  async findByEmail(email: string) {
    return this.repo.findOne({ where: { email } });
  }

  async findById(id: string) {
    return this.repo.findOne({ where: { id } });
  }

  async create(email: string, passwordHash: string) {
    const user = this.repo.create({ email, passwordHash });
    return this.repo.save(user);
  }

  async setCurrentRefreshTokenHash(userId: string, hash: string | null) {
    await this.repo.update(userId, { currentRefreshTokenHash: hash });
  }
}
