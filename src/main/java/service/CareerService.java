package service;

import model.Career;

import java.util.List;

public interface CareerService {
    Career getCareerById(int id) throws Exception;
    List<Career> getAllCareer() throws Exception;
}
