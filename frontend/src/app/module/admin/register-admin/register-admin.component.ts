import { Component, OnInit } from '@angular/core';
import { FormControl, FormControlName, FormGroup, Validators } from '@angular/forms';
import {MessageService} from 'primeng/api';


import {AuthService} from 'src/app/zynerator/security/shared/service/Auth.service';
import {UserDto} from 'src/app/zynerator/security/shared/model/User.model';
import {RoleDto} from 'src/app/zynerator/security/shared/model/Role.model';
import {RoleUserDto} from 'src/app/zynerator/security/shared/model/RoleUser.model';


@Component({
  selector: 'app-register-admin',
  templateUrl: './register-admin.component.html',
  styleUrls: ['./register-admin.component.css']
})
export class RegisterAdminComponent implements OnInit {

  clicked = false;
  registerForm = new FormGroup({
    phone : new FormControl('', Validators.required),
    firstName : new FormControl('', Validators.required),
    lastName : new FormControl('', Validators.required),
    email : new FormControl('', Validators.required),
    username : new FormControl('', Validators.required),
    password : new FormControl('', Validators.required)
  });

  constructor(private authService: AuthService, private messageService: MessageService) { }

  ngOnInit(): void {
  }


  submit(){
        this.clicked = true;
        if (this.registerForm.valid) {
        const formValues = this.registerForm.value
        const {phone,firstName, lastName, email ,username, password } = formValues;

		const role = new RoleDto();
		role.authority = 'ROLE_ADMIN' ;
		const roleUser = new RoleUserDto();
		roleUser.role = role;
		this.user.accountNonExpired=true;
		this.user.accountNonLocked=true;
		this.user.credentialsNonExpired=true;
		this.user.enabled=false;
		this.user.passwordChanged=false;
		this.user.firstName = firstName;
		this.user.lastName = lastName;
		this.user.phone = phone;
		this.user.username = username;
		this.user.password = password;
		this.user.email = email;
		this.user.roleUsers = new Array<RoleUserDto>();
		this.user.roleUsers.push(roleUser);
		this.authService.register();

	}else{
		this.messageService.add({
			severity: 'error',
			summary: 'Error',
			detail:  'fill in all fields'
		});
	}
 }

  get user(): UserDto {
    return this.authService.user;
  }

  set user(value: UserDto) {
    this.authService.user = value;
  }

}
